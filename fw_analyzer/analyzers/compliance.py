"""
fw_analyzer/analyzers/compliance.py

合规检查。

检查项：
  PERMIT_ANY_ANY      - 存在 permit any any 规则
  NO_IMPLICIT_DENY    - 策略末尾没有明确的 deny all 规则
  CLEARTEXT           - permit 规则允许明文协议（telnet/ftp/http 等）
  HIGH_RISK_PORT      - permit 规则允许高危端口
  NO_COMMENT          - permit 规则没有注释/描述
  DISABLED_RULES      - 存在禁用的规则（可能是遗留规则）
"""
from __future__ import annotations

from ..models.rule import FlatRule, Warning, WarningSeverity
from ..models.object_store import AddressObject, ServiceObject
from ..config import AnalyzerConfig


class ComplianceAnalyzer:
    """
    合规检查分析器。

    调用 analyze(rules, config) 后：
    - 规则级别的合规问题写入 rule.analysis_tags
    - 文件级别的合规问题作为 Warning 列表返回
    """

    def analyze(
        self,
        rules: list[FlatRule],
        config: AnalyzerConfig,
    ) -> list[Warning]:
        """
        执行所有合规检查。

        Returns:
            文件级别的合规告警列表（规则级别的直接写入 rule.analysis_tags）
        """
        comp = config.compliance
        global_warnings: list[Warning] = []
        disabled_count = 0

        for rule in rules:
            if not rule.enabled:
                # DISABLED_RULES — tag on the rule
                if comp.check_disabled_rules:
                    tag = "COMPLIANCE:DISABLED_RULES"
                    if tag not in rule.analysis_tags:
                        rule.analysis_tags.append(tag)
                    disabled_count += 1
                continue

            if rule.action != "permit":
                continue

            # PERMIT_ANY_ANY
            if comp.check_permit_any_any:
                if self._is_permit_any_any(rule):
                    tag = "COMPLIANCE:PERMIT_ANY_ANY"
                    if tag not in rule.analysis_tags:
                        rule.analysis_tags.append(tag)

            # NO_COMMENT
            if comp.check_no_comment:
                if not rule.comment.strip():
                    tag = "COMPLIANCE:NO_COMMENT"
                    if tag not in rule.analysis_tags:
                        rule.analysis_tags.append(tag)

            # CLEARTEXT
            if comp.check_cleartext:
                cleartext_ports = self._check_cleartext(rule, comp.cleartext_ports)
                for port in cleartext_ports:
                    tag = f"COMPLIANCE:CLEARTEXT:port={port}"
                    if tag not in rule.analysis_tags:
                        rule.analysis_tags.append(tag)

            # HIGH_RISK_PORT
            if comp.check_high_risk_ports:
                risk_ports = self._check_high_risk_ports(rule, config)
                for port in risk_ports:
                    tag = f"COMPLIANCE:HIGH_RISK_PORT:port={port}"
                    if tag not in rule.analysis_tags:
                        rule.analysis_tags.append(tag)

        # NO_IMPLICIT_DENY（文件级别）
        if comp.check_no_implicit_deny:
            if not self._has_implicit_deny(rules):
                global_warnings.append(Warning(
                    code="COMPLIANCE:NO_IMPLICIT_DENY",
                    message="策略末尾没有明确的 deny/drop all 规则，依赖隐式拒绝存在风险。",
                    severity=WarningSeverity.HIGH,
                ))

        # DISABLED_RULES（文件级别汇总告警）
        if comp.check_disabled_rules and disabled_count > 0:
            global_warnings.append(Warning(
                code="COMPLIANCE:DISABLED_RULES",
                message=f"存在 {disabled_count} 条禁用规则，可能是遗留配置，建议清理。",
                severity=WarningSeverity.LOW,
            ))

        return global_warnings

    # ------------------------------------------------------------------
    # 检查方法
    # ------------------------------------------------------------------

    def _is_permit_any_any(self, rule: FlatRule) -> bool:
        """判断规则是否为 permit any any（源/目的均为 any，服务为 any）。"""
        src_any = self._addr_is_any(rule.src_ip)
        dst_any = self._addr_is_any(rule.dst_ip)
        svc_any = self._svc_is_any(rule.services)

        return src_any and dst_any and svc_any

    def _check_cleartext(self, rule: FlatRule, cleartext_ports: list[int]) -> list[int]:
        """返回规则中允许的明文协议端口列表。"""
        if not rule.services:
            # any 服务，检查是否默认端口有明文
            return [p for p in cleartext_ports if p in (21, 23, 80)]

        result: list[int] = []
        for svc in rule.services:
            proto = svc.protocol.lower()
            for port in cleartext_ports:
                if svc.dst_port.low <= port <= svc.dst_port.high:
                    result.append(port)

        return sorted(set(result))

    def _check_high_risk_ports(
        self,
        rule: FlatRule,
        config: AnalyzerConfig,
    ) -> list[int]:
        """返回规则中允许的高危端口列表。"""
        if not rule.services:
            # any 服务：返回所有高危端口（只返回前 5 个避免噪音）
            return sorted(config.high_risk_tcp_ports)[:5]

        result: list[int] = []
        for svc in rule.services:
            proto = svc.protocol.lower()
            if proto in ("tcp", "tcp-udp", "any", "ip"):
                for port in config.high_risk_tcp_ports:
                    if svc.dst_port.low <= port <= svc.dst_port.high:
                        result.append(port)
            if proto in ("udp", "tcp-udp", "any", "ip"):
                for port in config.high_risk_udp_ports:
                    if svc.dst_port.low <= port <= svc.dst_port.high:
                        result.append(port)

        return sorted(set(result))

    def _has_implicit_deny(self, rules: list[FlatRule]) -> bool:
        """
        检查规则列表末尾是否有明确的 deny/drop all 规则。

        只检查最后 3 条 enabled 规则。
        """
        enabled = [r for r in rules if r.enabled]
        if not enabled:
            return False

        for rule in reversed(enabled[-3:]):
            if rule.action in ("deny", "drop", "reject"):
                src_any = self._addr_is_any(rule.src_ip)
                dst_any = self._addr_is_any(rule.dst_ip)
                svc_any = self._svc_is_any(rule.services)
                if src_any and dst_any and svc_any:
                    return True
        return False

    @staticmethod
    def _addr_is_any(addrs: list[AddressObject]) -> bool:
        if not addrs:
            return True
        for a in addrs:
            if a.type == "any":
                return True
            if a.network and str(a.network) == "0.0.0.0/0":
                return True
        return False

    @staticmethod
    def _svc_is_any(services: list[ServiceObject]) -> bool:
        """判断服务列表是否等价于 any（空列表或全部为 any 协议且端口全范围）。"""
        if not services:
            return True
        for svc in services:
            proto = svc.protocol.lower()
            if proto not in ("any", "ip"):
                return False
            # 检查端口范围是否覆盖全部（0-65535）
            if svc.dst_port.low != 0 or svc.dst_port.high != 65535:
                return False
        return True
