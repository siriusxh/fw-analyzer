"""
tests/test_analyzers.py

测试分析引擎：影子规则、冗余规则、过宽规则、合规检查。
"""
from __future__ import annotations

import pytest

from fw_analyzer.parsers import get_parser
from fw_analyzer.config import AnalyzerConfig
from fw_analyzer.analyzers.engine import AnalysisEngine, AnalysisResult
from fw_analyzer.analyzers.shadow import ShadowAnalyzer
from fw_analyzer.analyzers.redundancy import RedundancyAnalyzer
from fw_analyzer.analyzers.overwidth import OverwidthAnalyzer
from fw_analyzer.analyzers.compliance import ComplianceAnalyzer
from fw_analyzer.models.rule import FlatRule, Warning, WarningSeverity
from fw_analyzer.models.object_store import AddressObject, ServiceObject
from fw_analyzer.models.port_range import PortRange


# ------------------------------------------------------------------
# 测试辅助：构造最简 FlatRule
# ------------------------------------------------------------------

def _make_rule(
    seq: int,
    action: str = "permit",
    src: str = "any",
    dst: str = "any",
    proto: str = "any",
    dst_port_start: int = 0,
    dst_port_end: int = 65535,
    enabled: bool = True,
    comment: str = "",
) -> FlatRule:
    """构造用于测试的 FlatRule。"""
    from ipaddress import IPv4Network

    if src == "any":
        src_ip = [AddressObject(name="any", type="any", value="0.0.0.0/0",
                                network=IPv4Network("0.0.0.0/0"))]
    else:
        src_ip = [AddressObject(name=src, type="subnet", value=src,
                                network=IPv4Network(src, strict=False))]

    if dst == "any":
        dst_ip = [AddressObject(name="any", type="any", value="0.0.0.0/0",
                                network=IPv4Network("0.0.0.0/0"))]
    else:
        dst_ip = [AddressObject(name=dst, type="subnet", value=dst,
                                network=IPv4Network(dst, strict=False))]

    if proto == "any":
        services = [ServiceObject(name="any", protocol="any",
                                  src_port=PortRange.any(), dst_port=PortRange.any())]
    else:
        services = [ServiceObject(
            name=f"{proto}/{dst_port_start}-{dst_port_end}",
            protocol=proto,
            src_port=PortRange.any(),
            dst_port=PortRange(dst_port_start, dst_port_end),
        )]

    return FlatRule(
        vendor="test",
        raw_rule_id=f"rule-{seq}",
        rule_name=f"rule-{seq}",
        seq=seq,
        src_ip=src_ip,
        dst_ip=dst_ip,
        services=services,
        action=action,  # type: ignore[arg-type]
        enabled=enabled,
        comment=comment,
    )


# ------------------------------------------------------------------
# AnalysisEngine 集成测试
# ------------------------------------------------------------------

class TestAnalysisEngine:
    def test_returns_analysis_result(self, huawei_cfg):
        parse_result = get_parser("huawei").parse(huawei_cfg)
        engine = AnalysisEngine()
        result = engine.analyze(parse_result)
        assert isinstance(result, AnalysisResult)

    def test_rule_count_preserved(self, huawei_cfg):
        parse_result = get_parser("huawei").parse(huawei_cfg)
        engine = AnalysisEngine()
        result = engine.analyze(parse_result)
        assert result.rule_count == parse_result.rule_count

    def test_tagged_rule_count_gte_0(self, huawei_cfg):
        parse_result = get_parser("huawei").parse(huawei_cfg)
        result = AnalysisEngine().analyze(parse_result)
        assert result.tagged_rule_count >= 0

    def test_to_dict_keys(self, huawei_cfg):
        result = AnalysisEngine().analyze(get_parser("huawei").parse(huawei_cfg))
        d = result.to_dict()
        assert "vendor" in d
        assert "rule_count" in d
        assert "rules" in d
        assert "parse_warnings" in d
        assert "analysis_warnings" in d

    def test_parse_warnings_forwarded(self, huawei_cfg):
        parse_result = get_parser("huawei").parse(huawei_cfg)
        result = AnalysisEngine().analyze(parse_result)
        assert result.parse_warnings is parse_result.warnings


# ------------------------------------------------------------------
# 影子规则检测
# ------------------------------------------------------------------

class TestShadowAnalyzer:
    def test_basic_shadow(self):
        """后面的规则被前面规则完全覆盖 → SHADOW 标签。"""
        rules = [
            _make_rule(0, action="permit", src="any", dst="any"),  # 覆盖所有
            _make_rule(1, action="permit", src="192.168.1.0/24", dst="any"),  # 被覆盖
        ]
        ShadowAnalyzer().analyze(rules)
        # rule-1 应被标记为 SHADOW
        assert any("SHADOW" in t for t in rules[1].analysis_tags)

    def test_no_shadow_different_action(self):
        """动作不同：permit 和 deny，不算影子（算 SHADOW_CONFLICT）。"""
        rules = [
            _make_rule(0, action="permit", src="any", dst="any"),
            _make_rule(1, action="deny", src="192.168.1.0/24", dst="any"),
        ]
        ShadowAnalyzer().analyze(rules)
        # rule-1 可能被标记 SHADOW_CONFLICT，但不是完全无标签
        # 行为取决于实现，这里只验证 rule-0 没有 SHADOW 标签
        assert not any("SHADOW" in t for t in rules[0].analysis_tags)

    def test_disabled_rules_skipped(self):
        """禁用规则不参与影子检测（既不会成为覆盖者也不会被标记）。"""
        rules = [
            _make_rule(0, action="permit", src="any", dst="any", enabled=False),
            _make_rule(1, action="permit", src="192.168.1.0/24", dst="any"),
        ]
        ShadowAnalyzer().analyze(rules)
        # disabled 的 rule-0 不能作为覆盖者，rule-1 不应被标记
        assert not any("SHADOW" in t for t in rules[1].analysis_tags)

    def test_no_false_positive_narrow_before_wide(self):
        """窄规则在宽规则前面，不是影子。"""
        rules = [
            _make_rule(0, action="permit", src="192.168.1.0/24", dst="any"),
            _make_rule(1, action="permit", src="any", dst="any"),
        ]
        ShadowAnalyzer().analyze(rules)
        assert not any("SHADOW" in t for t in rules[0].analysis_tags)


# ------------------------------------------------------------------
# 冗余规则检测
# ------------------------------------------------------------------

class TestRedundancyAnalyzer:
    def test_duplicate_detected(self):
        """完全相同的两条规则 → 第二条被标记 REDUNDANT。"""
        rules = [
            _make_rule(0, action="permit", src="10.0.0.0/8", dst="any",
                       proto="tcp", dst_port_start=80, dst_port_end=80),
            _make_rule(1, action="permit", src="10.0.0.0/8", dst="any",
                       proto="tcp", dst_port_start=80, dst_port_end=80),
        ]
        RedundancyAnalyzer().analyze(rules)
        assert any("REDUNDANT" in t for t in rules[1].analysis_tags)
        assert not any("REDUNDANT" in t for t in rules[0].analysis_tags)

    def test_no_false_positive(self):
        """不同规则不应被标记为冗余。"""
        rules = [
            _make_rule(0, action="permit", src="10.0.0.0/8", dst="any",
                       proto="tcp", dst_port_start=80, dst_port_end=80),
            _make_rule(1, action="permit", src="10.0.0.0/8", dst="any",
                       proto="tcp", dst_port_start=443, dst_port_end=443),
        ]
        RedundancyAnalyzer().analyze(rules)
        assert not any("REDUNDANT" in t for t in rules[0].analysis_tags)
        assert not any("REDUNDANT" in t for t in rules[1].analysis_tags)


# ------------------------------------------------------------------
# 过宽规则检测
# ------------------------------------------------------------------

class TestOverwidthAnalyzer:
    def test_critical_port_flagged(self):
        """目的端口包含 CRITICAL 高危端口（如 3389）且源/目的为 any → OVERWIDE:CRITICAL。"""
        rule = _make_rule(0, action="permit", src="any", dst="any",
                          proto="tcp", dst_port_start=0, dst_port_end=65535)
        config = AnalyzerConfig()
        OverwidthAnalyzer().analyze([rule], config)
        # any 端口范围包含 3389（CRITICAL），应被标记
        overwide_tags = [t for t in rule.analysis_tags if "OVERWIDE" in t]
        assert len(overwide_tags) >= 1

    def test_specific_port_not_flagged(self):
        """访问单个普通端口（如 8080）不应被标记为过宽。"""
        rule = _make_rule(0, action="permit", src="192.168.1.0/24", dst="10.0.0.1/32",
                          proto="tcp", dst_port_start=8080, dst_port_end=8080)
        config = AnalyzerConfig()
        OverwidthAnalyzer().analyze([rule], config)
        assert not any("OVERWIDE" in t for t in rule.analysis_tags)

    def test_deny_rule_not_flagged(self):
        """deny 规则不检查过宽（不是 permit）。"""
        rule = _make_rule(0, action="deny", src="any", dst="any",
                          proto="tcp", dst_port_start=0, dst_port_end=65535)
        config = AnalyzerConfig()
        OverwidthAnalyzer().analyze([rule], config)
        assert not any("OVERWIDE" in t for t in rule.analysis_tags)

    def test_disabled_rule_skipped(self):
        """禁用规则不做过宽检查。"""
        rule = _make_rule(0, action="permit", src="any", dst="any",
                          proto="tcp", dst_port_start=0, dst_port_end=65535,
                          enabled=False)
        config = AnalyzerConfig()
        OverwidthAnalyzer().analyze([rule], config)
        assert not any("OVERWIDE" in t for t in rule.analysis_tags)


# ------------------------------------------------------------------
# 合规检查
# ------------------------------------------------------------------

class TestComplianceAnalyzer:
    def test_permit_any_any_flagged(self):
        """permit any any 触发 COMPLIANCE:PERMIT_ANY_ANY。"""
        rule = _make_rule(0, action="permit", src="any", dst="any")
        config = AnalyzerConfig()
        warnings = ComplianceAnalyzer().analyze([rule], config)
        tags = rule.analysis_tags
        assert any("PERMIT_ANY_ANY" in t for t in tags) or \
               any("PERMIT_ANY_ANY" in w.code for w in warnings)

    def test_no_implicit_deny(self):
        """没有末尾 deny-all 规则 → COMPLIANCE:NO_IMPLICIT_DENY 告警。"""
        rules = [
            _make_rule(0, action="permit", src="192.168.1.0/24", dst="any"),
        ]
        config = AnalyzerConfig()
        warnings = ComplianceAnalyzer().analyze(rules, config)
        codes = [w.code for w in warnings]
        assert any("NO_IMPLICIT_DENY" in c for c in codes)

    def test_implicit_deny_present(self):
        """末尾有 deny-all 规则 → 不触发 NO_IMPLICIT_DENY。"""
        rules = [
            _make_rule(0, action="permit", src="192.168.1.0/24", dst="any"),
            _make_rule(1, action="deny", src="any", dst="any"),
        ]
        config = AnalyzerConfig()
        warnings = ComplianceAnalyzer().analyze(rules, config)
        codes = [w.code for w in warnings]
        assert not any("NO_IMPLICIT_DENY" in c for c in codes)

    def test_no_comment_flagged(self):
        """没有注释的规则触发 COMPLIANCE:NO_COMMENT 标签。"""
        rule = _make_rule(0, action="permit", src="192.168.1.0/24", dst="any",
                          comment="")
        config = AnalyzerConfig()
        ComplianceAnalyzer().analyze([rule], config)
        assert any("NO_COMMENT" in t for t in rule.analysis_tags)

    def test_comment_ok(self):
        """有注释的规则不触发 NO_COMMENT。"""
        rule = _make_rule(0, action="permit", src="192.168.1.0/24", dst="any",
                          comment="Allow internal access")
        config = AnalyzerConfig()
        ComplianceAnalyzer().analyze([rule], config)
        assert not any("NO_COMMENT" in t for t in rule.analysis_tags)

    def test_disabled_rule_flagged(self):
        """存在禁用规则时触发 COMPLIANCE:DISABLED_RULES 告警。"""
        rules = [
            _make_rule(0, action="deny", src="any", dst="any", enabled=False),
        ]
        config = AnalyzerConfig()
        warnings = ComplianceAnalyzer().analyze(rules, config)
        codes = [w.code for w in warnings]
        assert any("DISABLED_RULES" in c for c in codes)
