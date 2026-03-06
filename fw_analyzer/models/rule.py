"""
fw_analyzer/models/rule.py

核心数据模型：Warning、FlatRule、ParseResult。

FlatRule 是所有厂商防火墙规则的统一表示，包含：
- 5元组（src_ip, dst_ip, protocol, src_port, dst_port）
- 动作与位置信息
- 解析阶段警告
- 分析阶段标签（analysis_tags）
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Literal

from .object_store import AddressObject, ServiceObject, StoreWarning


# ------------------------------------------------------------------
# 警告严重程度
# ------------------------------------------------------------------

class WarningSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    WARN = "warn"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    ERROR = "error"


# ------------------------------------------------------------------
# 警告
# ------------------------------------------------------------------

@dataclass
class Warning:
    """
    解析阶段或分析阶段产生的警告/告警。

    code 规范：
      解析警告：PARSE_WARN / FQDN_SKIP / NON_CONTIGUOUS_WILDCARD /
               DEEP_NESTING / CIRCULAR_REFERENCE / UNRESOLVED_OBJECT
      质量告警：SHADOW / SHADOW_CONFLICT / REDUNDANT /
               OVERWIDE:CRITICAL / OVERWIDE:HIGH / OVERWIDE:MEDIUM / OVERWIDE:LOW
      合规告警：COMPLIANCE:PERMIT_ANY_ANY / COMPLIANCE:NO_IMPLICIT_DENY /
               COMPLIANCE:CLEARTEXT / COMPLIANCE:HIGH_RISK_PORT /
               COMPLIANCE:NO_COMMENT / COMPLIANCE:DISABLED_RULES /
               COMPLIANCE:NO_TICKET / COMPLIANCE:NO_LOG
    """
    code: str
    message: str
    severity: WarningSeverity = WarningSeverity.WARN

    @staticmethod
    def from_store_warning(sw: StoreWarning) -> "Warning":
        sev_map = {
            "info": WarningSeverity.INFO,
            "warn": WarningSeverity.WARN,
            "error": WarningSeverity.ERROR,
        }
        return Warning(
            code=sw.code,
            message=sw.message,
            severity=sev_map.get(sw.severity, WarningSeverity.WARN),
        )

    def to_dict(self) -> dict:
        return {
            "code": self.code,
            "message": self.message,
            "severity": self.severity.value,
        }


# ------------------------------------------------------------------
# 核心规则模型
# ------------------------------------------------------------------

@dataclass
class FlatRule:
    """
    统一的防火墙规则表示（已展开对象组，每条原始规则对应一个 FlatRule）。

    5元组字段：
      src_ip   - 展开后的源地址对象列表（对象组已递归展开为叶子节点）
      dst_ip   - 展开后的目的地址对象列表
      services - 展开后的服务对象列表（含 protocol/src_port/dst_port）

    输出时多个对象用分号分隔，例如：
      src_ip_str()  → "192.168.1.0/24; 10.0.0.0/8"
      service_str() → "tcp/any/443; tcp/any/80"

    分析标签格式（analysis_tags）：
      "SHADOW:by=policy-3"
      "SHADOW_CONFLICT:by=policy-7"
      "REDUNDANT:dup_of=policy-2"
      "OVERWIDE:CRITICAL"
      "OVERWIDE:HIGH"
      "COMPLIANCE:CLEARTEXT:port=23"
    """

    # --- 来源信息 ---
    vendor: str                                     # "huawei" / "cisco-asa" / "paloalto" / "fortinet"
    raw_rule_id: str                                # 原始规则编号或名称
    rule_name: str                                  # 可读名称（部分厂商与 raw_rule_id 相同）
    seq: int                                        # 规则在策略列表中的顺序（从 0 开始）

    # --- 5元组 ---
    src_ip: list[AddressObject] = field(default_factory=list)
    dst_ip: list[AddressObject] = field(default_factory=list)
    services: list[ServiceObject] = field(default_factory=list)

    # --- 动作 ---
    action: Literal["permit", "deny", "drop", "reject"] = "deny"

    # --- 位置信息 ---
    src_zone: str = ""                              # 源安全域（PAN / Fortinet）
    dst_zone: str = ""                              # 目的安全域
    interface: str = ""                             # 接口（Cisco ASA）
    direction: Literal["inbound", "outbound", "both", ""] = ""

    # --- 元信息 ---
    enabled: bool = True
    log_enabled: bool = True                        # 是否开启日志记录（默认 True）
    comment: str = ""
    ticket: str = ""                                # ITO 工单号（从 rule_name/comment 提取）

    # --- 分析结果（分析器写入，初始为空）---
    analysis_tags: list[str] = field(default_factory=list)

    # --- 解析阶段警告 ---
    warnings: list[Warning] = field(default_factory=list)

    # ------------------------------------------------------------------
    # 输出辅助方法
    # ------------------------------------------------------------------

    def src_ip_str(self) -> str:
        """返回源地址字符串，多个用分号+空格分隔。"""
        return "; ".join(str(a) for a in self.src_ip) if self.src_ip else "any"

    def dst_ip_str(self) -> str:
        """返回目的地址字符串，多个用分号+空格分隔。"""
        return "; ".join(str(a) for a in self.dst_ip) if self.dst_ip else "any"

    def service_str(self) -> str:
        """
        返回服务字符串，多个用分号+空格分隔。
        格式：proto/src_port/dst_port，any 端口省略显示为 any。
        示例：tcp/any/443; udp/any/53
        """
        if not self.services:
            return "any"
        return "; ".join(str(s) for s in self.services)

    def protocol_str(self) -> str:
        """返回去重后的协议字符串列表，多个用分号分隔。"""
        protos = list(dict.fromkeys(s.protocol for s in self.services))
        return "; ".join(protos) if protos else "any"

    def dst_port_str(self) -> str:
        """返回目的端口字符串列表，多个用分号分隔。"""
        ports = list(dict.fromkeys(str(s.dst_port) for s in self.services))
        return "; ".join(ports) if ports else "any"

    def src_port_str(self) -> str:
        """返回源端口字符串列表，多个用分号分隔。"""
        ports = list(dict.fromkeys(str(s.src_port) for s in self.services))
        return "; ".join(ports) if ports else "any"

    def analysis_tags_str(self) -> str:
        """返回分析标签字符串，多个用 | 分隔。"""
        return " | ".join(self.analysis_tags) if self.analysis_tags else ""

    def warnings_str(self) -> str:
        """返回警告字符串，多个用 | 分隔。"""
        return " | ".join(w.code for w in self.warnings) if self.warnings else ""

    def to_dict(self) -> dict:
        """序列化为字典（供 JSON 导出使用）。"""
        return {
            "vendor": self.vendor,
            "raw_rule_id": self.raw_rule_id,
            "rule_name": self.rule_name,
            "seq": self.seq,
            "src_ip": [a.to_dict() for a in self.src_ip],
            "dst_ip": [a.to_dict() for a in self.dst_ip],
            "services": [s.to_dict() for s in self.services],
            "action": self.action,
            "src_zone": self.src_zone,
            "dst_zone": self.dst_zone,
            "interface": self.interface,
            "direction": self.direction,
            "enabled": self.enabled,
            "log_enabled": self.log_enabled,
            "comment": self.comment,
            "ticket": self.ticket,
            "analysis_tags": self.analysis_tags,
            "warnings": [w.to_dict() for w in self.warnings],
        }

    def to_csv_row(self) -> dict:
        """
        序列化为 CSV 行字典。

        多值字段用分号分隔，便于 Excel 阅读。
        """
        return {
            "rule_id": self.raw_rule_id,
            "rule_name": self.rule_name,
            "seq": self.seq,
            "action": self.action,
            "src_ip": self.src_ip_str(),
            "dst_ip": self.dst_ip_str(),
            "protocol": self.protocol_str(),
            "src_port": self.src_port_str(),
            "dst_port": self.dst_port_str(),
            "services": self.service_str(),
            "src_zone": self.src_zone,
            "dst_zone": self.dst_zone,
            "interface": self.interface,
            "direction": self.direction,
            "enabled": self.enabled,
            "log_enabled": self.log_enabled,
            "comment": self.comment,
            "ticket": self.ticket,
            "analysis_tags": self.analysis_tags_str(),
            "warnings": self.warnings_str(),
            "vendor": self.vendor,
        }


# ------------------------------------------------------------------
# 解析结果
# ------------------------------------------------------------------

@dataclass
class ParseResult:
    """
    单个配置文件的解析结果。

    包含规则列表和全局警告（非规则级别的文件级别警告）。
    """
    rules: list[FlatRule]
    warnings: list[Warning]      # 文件级别全局警告
    vendor: str                  # 识别或指定的厂商
    source_file: str             # 原始文件名/路径

    @property
    def rule_count(self) -> int:
        return len(self.rules)

    @property
    def enabled_rule_count(self) -> int:
        return sum(1 for r in self.rules if r.enabled)

    def to_dict(self) -> dict:
        return {
            "vendor": self.vendor,
            "source_file": self.source_file,
            "rule_count": self.rule_count,
            "enabled_rule_count": self.enabled_rule_count,
            "warnings": [w.to_dict() for w in self.warnings],
            "rules": [r.to_dict() for r in self.rules],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)
