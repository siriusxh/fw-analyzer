"""
fw_analyzer/trace.py

访问需求命中分析（Trace）。

功能：给定源/目的 IP、协议、端口，在规则列表中按 first-match 语义找出命中的规则。

使用方式：
  engine = TraceEngine(rules)
  result = engine.trace(TraceQuery(
      src_ip="10.0.0.1/32",
      dst_ip="8.8.8.8/32",
      protocol="udp",
      dst_port=53,
  ))
  print(result.matched_rule.rule_name, result.action)

匹配语义：
  - /32 单 IP：被规则中任意地址对象包含即命中（存在量词）
  - 网段查询：被规则中某单一地址对象完全覆盖才命中（query.subnet_of(obj.network)）
  - 协议匹配：规则为 any 则匹配所有协议
  - 端口匹配：规则端口范围包含查询端口即命中
  - disabled 规则：跳过
  - FQDN 地址对象：跳过（附说明）
"""
from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from ipaddress import IPv4Network
from typing import Optional

from .models.rule import FlatRule
from .models.object_store import AddressObject, ServiceObject
from .models.ip_utils import parse_ipv4_network, network_contains
from .models.port_range import PortRange


# ------------------------------------------------------------------
# 查询请求
# ------------------------------------------------------------------

@dataclass
class TraceQuery:
    """
    单条 Trace 查询请求。

    IP 格式：CIDR（如 "10.0.0.1/32" 或 "10.0.0.0/24"），单 IP 可省略 /32。
    """
    src_ip: str                     # 源 IP（CIDR 或单 IP）
    dst_ip: str                     # 目的 IP（CIDR 或单 IP）
    protocol: str = "any"           # 协议："tcp" / "udp" / "icmp" / "any"
    dst_port: int = 0               # 目的端口（0 表示 any/不限）
    src_port: int = 0               # 源端口（0 表示 any/不限）
    label: str = ""                 # 可选标签（批量查询时用于标识行）

    def __post_init__(self) -> None:
        # 规范化 IP 格式
        self.src_ip = self._normalize_ip(self.src_ip)
        self.dst_ip = self._normalize_ip(self.dst_ip)
        self.protocol = self.protocol.lower()

    @staticmethod
    def _normalize_ip(ip: str) -> str:
        """将 IP 规范化为 CIDR 格式。"""
        ip = ip.strip()
        if "/" not in ip:
            ip = f"{ip}/32"
        return ip

    @property
    def src_network(self) -> IPv4Network:
        return parse_ipv4_network(self.src_ip)

    @property
    def dst_network(self) -> IPv4Network:
        return parse_ipv4_network(self.dst_ip)

    def to_dict(self) -> dict:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "dst_port": self.dst_port,
            "src_port": self.src_port,
            "label": self.label,
        }


# ------------------------------------------------------------------
# 查询结果
# ------------------------------------------------------------------

@dataclass
class TraceResult:
    """单条 Trace 查询的结果。"""
    query: TraceQuery
    matched: bool = False
    matched_rule: Optional[FlatRule] = None
    action: str = "no-match"        # "permit" / "deny" / "drop" / "reject" / "no-match"
    match_note: str = ""            # 说明（如跳过了哪些 FQDN 对象）
    all_matches: list[FlatRule] = field(default_factory=list)

    def to_dict(self) -> dict:
        base = self.query.to_dict()
        base.update({
            "matched": self.matched,
            "matched_rule_id": self.matched_rule.raw_rule_id if self.matched_rule else "",
            "matched_rule_name": self.matched_rule.rule_name if self.matched_rule else "",
            "matched_seq": self.matched_rule.seq if self.matched_rule else -1,
            "action": self.action,
            "match_note": self.match_note,
        })
        return base

    def to_csv_row(self) -> dict:
        return self.to_dict()


# ------------------------------------------------------------------
# 匹配引擎
# ------------------------------------------------------------------

class TraceEngine:
    """
    防火墙规则 Trace 引擎。

    初始化时传入规则列表，支持单条查询和批量查询。
    """

    def __init__(self, rules: list[FlatRule]) -> None:
        self.rules = rules

    def trace(
        self,
        query: TraceQuery,
        first_match_only: bool = True,
    ) -> TraceResult:
        """
        对单条查询进行 Trace，返回 TraceResult。

        Args:
            query:           查询请求
            first_match_only: True（默认）返回第一条命中规则；
                              False 返回所有命中规则（存于 result.all_matches）
        """
        try:
            src_net = query.src_network
            dst_net = query.dst_network
        except ValueError as e:
            return TraceResult(
                query=query,
                matched=False,
                action="no-match",
                match_note=f"查询 IP 解析失败: {e}",
            )

        notes: list[str] = []
        all_matches: list[FlatRule] = []

        for rule in self.rules:
            if not rule.enabled:
                continue

            match, note = self._match_rule(rule, src_net, dst_net, query)
            if note:
                notes.append(note)
            if match:
                all_matches.append(rule)
                if first_match_only:
                    return TraceResult(
                        query=query,
                        matched=True,
                        matched_rule=rule,
                        action=rule.action,
                        match_note="; ".join(notes),
                        all_matches=[rule],
                    )

        if all_matches:
            return TraceResult(
                query=query,
                matched=True,
                matched_rule=all_matches[0],
                action=all_matches[0].action,
                match_note="; ".join(notes),
                all_matches=all_matches,
            )

        return TraceResult(
            query=query,
            matched=False,
            action="no-match",
            match_note="; ".join(notes) if notes else "无规则命中（隐式拒绝）",
        )

    def trace_batch(
        self,
        queries: list[TraceQuery],
        first_match_only: bool = True,
    ) -> list[TraceResult]:
        """批量 Trace，返回结果列表（顺序与输入对应）。"""
        return [self.trace(q, first_match_only) for q in queries]

    # ------------------------------------------------------------------
    # 单规则匹配逻辑
    # ------------------------------------------------------------------

    def _match_rule(
        self,
        rule: FlatRule,
        src_net: IPv4Network,
        dst_net: IPv4Network,
        query: TraceQuery,
    ) -> tuple[bool, str]:
        """
        检查单条规则是否命中查询，返回 (是否命中, 说明)。

        说明字段用于记录跳过的 FQDN 对象等信息。
        """
        note = ""

        # --- 源地址匹配 ---
        src_match, src_note = self._match_address_list(rule.src_ip, src_net, "src")
        if not src_match:
            return False, src_note

        # --- 目的地址匹配 ---
        dst_match, dst_note = self._match_address_list(rule.dst_ip, dst_net, "dst")
        if not dst_match:
            return False, dst_note

        if src_note:
            note += src_note + " "
        if dst_note:
            note += dst_note + " "

        # --- 服务/协议/端口匹配 ---
        svc_match, svc_note = self._match_service_list(rule.services, query)
        if not svc_match:
            return False, svc_note
        if svc_note:
            note += svc_note

        return True, note.strip()

    def _match_address_list(
        self,
        addr_list: list[AddressObject],
        query_net: IPv4Network,
        direction: str,
    ) -> tuple[bool, str]:
        """
        检查地址对象列表是否命中查询网段。

        匹配语义：
          - /32 单 IP：被列表中任意对象包含即命中（存在量词）
          - 网段查询：被列表中某单一对象完全覆盖才命中
            （query_net.subnet_of(obj.network) == True）

        FQDN/unknown/range 对象：跳过，并在 note 中记录。
        """
        # 空列表等同于 any
        if not addr_list:
            return True, ""

        is_single_ip = query_net.prefixlen == 32
        skipped_fqdn: list[str] = []

        for obj in addr_list:
            if obj.type == "any":
                return True, ""

            if obj.type in ("fqdn", "unknown"):
                skipped_fqdn.append(obj.value)
                continue

            if obj.type == "range":
                # IP 范围（如 10.0.0.1-10.0.0.10）：简单字符串匹配，无法做 subnet 判断
                # 跳过并标记
                skipped_fqdn.append(f"range:{obj.value}")
                continue

            if obj.network is None:
                skipped_fqdn.append(obj.value)
                continue

            if is_single_ip:
                # 单 IP 查询：query 被 obj 包含即命中
                if network_contains(obj.network, query_net):
                    return True, ""
            else:
                # 网段查询：query 必须是 obj 的子网或等于 obj
                try:
                    if query_net.subnet_of(obj.network):
                        return True, ""
                except TypeError:
                    pass

        note = ""
        if skipped_fqdn:
            note = f"[{direction} 跳过 FQDN/range 对象: {', '.join(skipped_fqdn[:3])}]"

        return False, note

    def _match_service_list(
        self,
        services: list[ServiceObject],
        query: TraceQuery,
    ) -> tuple[bool, str]:
        """
        检查服务对象列表是否命中查询的协议+端口。

        空服务列表等同于 any（匹配所有）。
        """
        if not services:
            return True, ""

        for svc in services:
            if self._match_service(svc, query):
                return True, ""

        return False, ""

    def _match_service(self, svc: ServiceObject, query: TraceQuery) -> bool:
        """检查单个服务对象是否命中查询。"""
        # 协议匹配
        proto = svc.protocol.lower()
        query_proto = query.protocol.lower()

        if proto not in ("any", "ip"):
            if query_proto not in ("any", "ip"):
                if proto == "tcp-udp":
                    if query_proto not in ("tcp", "udp"):
                        return False
                elif proto != query_proto:
                    return False

        # 目的端口匹配
        if query.dst_port and query.dst_port != 0:
            if not svc.dst_port.is_any():
                if not svc.dst_port.contains(PortRange.single(query.dst_port)):
                    return False

        # 源端口匹配（如果查询指定了源端口）
        if query.src_port and query.src_port != 0:
            if not svc.src_port.is_any():
                if not svc.src_port.contains(PortRange.single(query.src_port)):
                    return False

        return True


# ------------------------------------------------------------------
# 批量查询 CSV 加载
# ------------------------------------------------------------------

def load_trace_queries_from_csv(content: str) -> list[TraceQuery]:
    """
    从 CSV 文本加载批量 Trace 查询。

    CSV 列（顺序）：
      src_ip, dst_ip, protocol, dst_port [, src_port] [, label]

    示例：
      10.0.0.1,8.8.8.8,udp,53
      10.0.0.0/24,0.0.0.0/0,tcp,443,,web-access

    Args:
        content: CSV 文本内容

    Returns:
        TraceQuery 列表
    """
    queries: list[TraceQuery] = []
    reader = csv.DictReader(
        io.StringIO(content),
        fieldnames=["src_ip", "dst_ip", "protocol", "dst_port", "src_port", "label"],
    )

    for row in reader:
        # 跳过注释行和空行
        src = (row.get("src_ip") or "").strip()
        if not src or src.startswith("#"):
            continue

        try:
            queries.append(TraceQuery(
                src_ip=src,
                dst_ip=(row.get("dst_ip") or "").strip(),
                protocol=(row.get("protocol") or "any").strip() or "any",
                dst_port=int((row.get("dst_port") or "0").strip() or 0),
                src_port=int((row.get("src_port") or "0").strip() or 0),
                label=(row.get("label") or "").strip(),
            ))
        except (ValueError, KeyError):
            # 跳过无法解析的行
            continue

    return queries
