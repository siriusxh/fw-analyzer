"""
fw_analyzer/analyzers/shadow.py

影子规则检测。

定义：规则 B 是规则 A 的影子规则，当且仅当：
  1. A 在 B 之前（seq_A < seq_B）
  2. A 的流量覆盖范围完全包含 B 的覆盖范围（A ⊇ B）
  3. 如果 A 与 B 动作相同 → B 是冗余型影子（SHADOW）
  4. 如果 A 与 B 动作不同 → B 是冲突型影子（SHADOW_CONFLICT）

覆盖语义（B 被 A 完全覆盖）：
  - 对于 B 的每个源地址对象，A 中存在某个对象完全包含它
  - 对于 B 的每个目的地址对象，A 中存在某个对象完全包含它
  - 对于 B 的每个服务对象，A 中存在某个服务对象完全包含它

性能优化：
  - 跳过 disabled 规则
  - 协议剪枝：若 A 与 B 协议集合无交集，跳过
  - IP overlap 剪枝：若源/目的地址无 overlap，跳过
"""
from __future__ import annotations

from ipaddress import IPv4Network

from ..models.rule import FlatRule, Warning, WarningSeverity
from ..models.object_store import AddressObject, ServiceObject
from ..models.port_range import PortRange
from ..models.ip_utils import network_contains


class ShadowAnalyzer:
    """
    影子规则分析器。

    调用 analyze(rules) 后，规则的 analysis_tags 会被原地修改。
    """

    def analyze(self, rules: list[FlatRule]) -> None:
        """
        检测影子规则，将标签写入 rule.analysis_tags。

        标签格式：
          "SHADOW:by={rule_id}"         - 被完全覆盖且动作相同
          "SHADOW_CONFLICT:by={rule_id}" - 被完全覆盖但动作不同
        """
        enabled = [r for r in rules if r.enabled]

        for i, rule_b in enumerate(enabled):
            for j in range(i):
                rule_a = enabled[j]

                # --- 协议剪枝 ---
                if not self._protocols_may_overlap(rule_a, rule_b):
                    continue

                # --- IP 快速 overlap 剪枝（任意 src 对有 overlap 才继续）---
                if not self._ips_may_overlap(rule_a.src_ip, rule_b.src_ip):
                    continue
                if not self._ips_may_overlap(rule_a.dst_ip, rule_b.dst_ip):
                    continue

                # --- 精确覆盖检查 ---
                if self._a_covers_b(rule_a, rule_b):
                    if rule_a.action == rule_b.action:
                        tag = f"SHADOW:by={rule_a.raw_rule_id}"
                    else:
                        tag = f"SHADOW_CONFLICT:by={rule_a.raw_rule_id}"
                    if tag not in rule_b.analysis_tags:
                        rule_b.analysis_tags.append(tag)

    # ------------------------------------------------------------------
    # 覆盖检查
    # ------------------------------------------------------------------

    def _a_covers_b(self, rule_a: FlatRule, rule_b: FlatRule) -> bool:
        """
        判断 rule_a 是否完全覆盖 rule_b。

        覆盖 = 对于 B 的每一个地址/服务对象，A 中都有某个对象包含它。
        """
        # 源地址：B 的每个 src 对象必须被 A 的某个 src 对象包含
        if not self._addr_list_b_covered_by_a(rule_b.src_ip, rule_a.src_ip):
            return False

        # 目的地址
        if not self._addr_list_b_covered_by_a(rule_b.dst_ip, rule_a.dst_ip):
            return False

        # 服务
        if not self._svc_list_b_covered_by_a(rule_b.services, rule_a.services):
            return False

        return True

    def _addr_list_b_covered_by_a(
        self,
        b_addrs: list[AddressObject],
        a_addrs: list[AddressObject],
    ) -> bool:
        """
        对于 B 的每个地址对象，A 中是否存在某个地址对象完全包含它。
        """
        # B 为空 = any；A 需要也是 any 才算覆盖
        if not b_addrs:
            return self._addr_list_is_any(a_addrs)

        # A 为 any，直接覆盖
        if self._addr_list_is_any(a_addrs):
            return True

        for b_obj in b_addrs:
            covered = False
            for a_obj in a_addrs:
                if self._addr_a_covers_b(a_obj, b_obj):
                    covered = True
                    break
            if not covered:
                return False
        return True

    def _addr_a_covers_b(self, a: AddressObject, b: AddressObject) -> bool:
        """判断地址对象 a 是否包含 b。"""
        if a.type == "any":
            return True
        if b.type == "any":
            return a.type == "any"

        # FQDN/range/unknown 无法判断，保守返回 False
        if a.type in ("fqdn", "range", "unknown") or b.type in ("fqdn", "range", "unknown"):
            return False

        if a.network is None or b.network is None:
            return False

        return network_contains(a.network, b.network)

    @staticmethod
    def _addr_list_is_any(addrs: list[AddressObject]) -> bool:
        if not addrs:
            return True
        for a in addrs:
            if a.type == "any":
                return True
        return False

    def _svc_list_b_covered_by_a(
        self,
        b_svcs: list[ServiceObject],
        a_svcs: list[ServiceObject],
    ) -> bool:
        """
        对于 B 的每个服务对象，A 中是否存在某个服务对象完全包含它。
        """
        # 空 = any
        if not b_svcs:
            return not a_svcs  # A 也必须是 any

        if not a_svcs:  # A 是 any，覆盖一切
            return True

        for b_svc in b_svcs:
            covered = False
            for a_svc in a_svcs:
                if self._svc_a_covers_b(a_svc, b_svc):
                    covered = True
                    break
            if not covered:
                return False
        return True

    def _svc_a_covers_b(self, a: ServiceObject, b: ServiceObject) -> bool:
        """判断服务对象 a 是否包含 b。"""
        # 协议匹配
        a_proto = a.protocol.lower()
        b_proto = b.protocol.lower()

        if a_proto not in ("any", "ip"):
            if b_proto in ("any", "ip"):
                return False  # A 是具体协议，B 是 any，A 不能覆盖 B
            if a_proto == "tcp-udp":
                if b_proto not in ("tcp", "udp"):
                    return False
            elif a_proto != b_proto:
                return False

        # 端口匹配：a 的端口范围必须包含 b 的端口范围
        if not a.dst_port.contains(b.dst_port):
            return False
        if not a.src_port.contains(b.src_port):
            return False

        return True

    # ------------------------------------------------------------------
    # 剪枝方法
    # ------------------------------------------------------------------

    def _protocols_may_overlap(self, rule_a: FlatRule, rule_b: FlatRule) -> bool:
        """快速检查两条规则的协议集合是否可能有交集。"""
        a_protos = self._get_protocols(rule_a)
        b_protos = self._get_protocols(rule_b)

        # any 与任何协议都有交集
        if "any" in a_protos or "any" in b_protos:
            return True

        # tcp-udp 展开
        if "tcp-udp" in a_protos:
            a_protos = (a_protos - {"tcp-udp"}) | {"tcp", "udp"}
        if "tcp-udp" in b_protos:
            b_protos = (b_protos - {"tcp-udp"}) | {"tcp", "udp"}

        return bool(a_protos & b_protos)

    @staticmethod
    def _get_protocols(rule: FlatRule) -> set[str]:
        if not rule.services:
            return {"any"}
        return {s.protocol.lower() for s in rule.services}

    def _ips_may_overlap(
        self,
        a_addrs: list[AddressObject],
        b_addrs: list[AddressObject],
    ) -> bool:
        """快速检查两个地址列表是否存在 IP 重叠（用于剪枝）。"""
        if not a_addrs or not b_addrs:
            return True  # any 与任何地址都可能重叠

        for a in a_addrs:
            if a.type == "any":
                return True
            for b in b_addrs:
                if b.type == "any":
                    return True
                if a.network and b.network:
                    if a.network.overlaps(b.network):
                        return True
        return False
