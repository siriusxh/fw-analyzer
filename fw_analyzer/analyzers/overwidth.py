"""
fw_analyzer/analyzers/overwidth.py

过宽规则检测。

定义：规则的目的/源 IP 或服务范围过于宽泛，且命中了高危端口，存在安全风险。

分级（根据目的端口所在的风险列表）：
  CRITICAL > HIGH > MEDIUM > LOW

触发条件（满足任一）：
  - 源 IP 为 any（0.0.0.0/0）
  - 目的 IP 为 any（0.0.0.0/0）
  同时目的端口命中高危端口列表

对于 PERMIT 规则才检测过宽，DENY/DROP 规则不检测。
"""
from __future__ import annotations

from ..models.rule import FlatRule
from ..models.object_store import AddressObject, ServiceObject
from ..config import AnalyzerConfig


class OverwidthAnalyzer:
    """
    过宽规则分析器。

    调用 analyze(rules, config) 后，过宽规则的 analysis_tags 会被原地修改。
    """

    def analyze(self, rules: list[FlatRule], config: AnalyzerConfig) -> None:
        """
        检测过宽规则，将标签写入 rule.analysis_tags。

        标签格式：
          "OVERWIDE:CRITICAL"
          "OVERWIDE:HIGH"
          "OVERWIDE:MEDIUM"
          "OVERWIDE:LOW"
        """
        for rule in rules:
            if not rule.enabled:
                continue
            if rule.action not in ("permit",):
                continue

            self._check_rule(rule, config)

    def _check_rule(self, rule: FlatRule, config: AnalyzerConfig) -> None:
        """检查单条规则是否过宽。"""
        src_is_any = self._addr_is_any(rule.src_ip)
        dst_is_any = self._addr_is_any(rule.dst_ip)

        # 如果源和目的都不是 any，则不视为过宽
        if not src_is_any and not dst_is_any:
            return

        # 服务为 any，找出最高严重等级
        if not rule.services:
            # 服务 any 包含所有端口，取最高级
            severity = "LOW"  # 至少是 LOW
            # 检查是否有任何 CRITICAL 端口在默认列表中
            if config.overwide.critical_ports:
                severity = "CRITICAL"
            elif config.overwide.high_ports:
                severity = "HIGH"
            elif config.overwide.medium_ports:
                severity = "MEDIUM"
            tag = f"OVERWIDE:{severity}"
            if tag not in rule.analysis_tags:
                rule.analysis_tags.append(tag)
            return

        # 遍历服务对象，找出命中的最高级别
        highest: str | None = None
        for svc in rule.services:
            sev = self._get_service_severity(svc, config)
            if sev:
                highest = self._max_severity(highest, sev)

        if highest:
            tag = f"OVERWIDE:{highest}"
            if tag not in rule.analysis_tags:
                rule.analysis_tags.append(tag)

    def _get_service_severity(
        self,
        svc: ServiceObject,
        config: AnalyzerConfig,
    ) -> str | None:
        """返回服务对象对应的最高过宽严重等级。"""
        proto = svc.protocol.lower()
        dst_port = svc.dst_port

        if dst_port.is_any():
            # 端口 any，取最高级别
            if config.overwide.critical_ports:
                return "CRITICAL"
            if config.overwide.high_ports:
                return "HIGH"
            if config.overwide.medium_ports:
                return "MEDIUM"
            return "LOW"

        # 遍历端口范围内的高危端口
        # 对于大范围端口，只检查已知高危端口列表中是否有交集
        all_risk_ports = (
            [(p, "CRITICAL") for p in config.overwide.critical_ports] +
            [(p, "HIGH") for p in config.overwide.high_ports] +
            [(p, "MEDIUM") for p in config.overwide.medium_ports] +
            [(p, "LOW") for p in config.overwide.low_ports]
        )

        highest: str | None = None
        for port, sev in all_risk_ports:
            if dst_port.low <= port <= dst_port.high:
                highest = self._max_severity(highest, sev)

        return highest

    @staticmethod
    def _addr_is_any(addrs: list[AddressObject]) -> bool:
        """判断地址列表是否等同于 any。"""
        if not addrs:
            return True
        for a in addrs:
            if a.type == "any":
                return True
            if a.network and str(a.network) == "0.0.0.0/0":
                return True
        return False

    @staticmethod
    def _max_severity(current: str | None, new: str) -> str:
        """返回两个严重等级中更高的那个。"""
        order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        if current is None:
            return new
        return current if order.get(current, 0) >= order.get(new, 0) else new
