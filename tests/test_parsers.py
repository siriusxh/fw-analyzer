"""
tests/test_parsers.py

测试各厂商解析器：规则数量、动作、地址对象展开、服务解析。
"""
from __future__ import annotations

import pytest

from fw_analyzer.parsers import get_parser, detect_vendor
from fw_analyzer.models.rule import FlatRule, ParseResult


# ------------------------------------------------------------------
# detect_vendor 测试
# ------------------------------------------------------------------

class TestDetectVendor:
    def test_detect_huawei(self, huawei_cfg):
        assert detect_vendor(huawei_cfg) == "huawei"

    def test_detect_cisco(self, cisco_cfg):
        assert detect_vendor(cisco_cfg) == "cisco-asa"

    def test_detect_paloalto(self, paloalto_cfg):
        assert detect_vendor(paloalto_cfg) == "paloalto"

    def test_detect_fortinet(self, fortinet_cfg):
        assert detect_vendor(fortinet_cfg) == "fortinet"

    def test_detect_unknown(self):
        assert detect_vendor("random text that matches nothing") == "unknown"


# ------------------------------------------------------------------
# 华为解析器
# ------------------------------------------------------------------

class TestHuaweiParser:
    def test_parse_returns_result(self, huawei_cfg):
        parser = get_parser("huawei")
        result = parser.parse(huawei_cfg, source_file="huawei_simple.cfg")
        assert isinstance(result, ParseResult)
        assert result.vendor == "huawei"
        assert result.source_file == "huawei_simple.cfg"

    def test_rule_count(self, huawei_cfg):
        result = get_parser("huawei").parse(huawei_cfg)
        # fixture 有 4 条规则
        assert result.rule_count >= 3

    def test_permit_rule(self, huawei_cfg):
        result = get_parser("huawei").parse(huawei_cfg)
        permits = [r for r in result.rules if r.action == "permit"]
        assert len(permits) >= 1

    def test_deny_rule(self, huawei_cfg):
        result = get_parser("huawei").parse(huawei_cfg)
        denies = [r for r in result.rules if r.action == "deny"]
        assert len(denies) >= 1

    def test_rule_has_src_ip(self, huawei_cfg):
        result = get_parser("huawei").parse(huawei_cfg)
        # 至少有一条规则有源 IP
        rules_with_src = [r for r in result.rules if r.src_ip]
        assert len(rules_with_src) >= 1

    def test_rule_seq_sequential(self, huawei_cfg):
        result = get_parser("huawei").parse(huawei_cfg)
        seqs = [r.seq for r in result.rules]
        assert seqs == list(range(len(seqs)))

    def test_flat_rule_fields(self, huawei_cfg):
        result = get_parser("huawei").parse(huawei_cfg)
        for rule in result.rules:
            assert isinstance(rule, FlatRule)
            assert rule.vendor == "huawei"
            assert rule.action in ("permit", "deny", "drop", "reject")
            assert isinstance(rule.enabled, bool)


# ------------------------------------------------------------------
# Cisco ASA 解析器
# ------------------------------------------------------------------

class TestCiscoAsaParser:
    def test_parse_returns_result(self, cisco_cfg):
        result = get_parser("cisco-asa").parse(cisco_cfg, source_file="cisco_asa_simple.cfg")
        assert isinstance(result, ParseResult)
        assert result.vendor == "cisco-asa"

    def test_rule_count(self, cisco_cfg):
        result = get_parser("cisco-asa").parse(cisco_cfg)
        assert result.rule_count >= 2

    def test_object_group_expanded(self, cisco_cfg):
        """object-group internal-nets 应展开为多个地址对象。"""
        result = get_parser("cisco-asa").parse(cisco_cfg)
        rules = [r for r in result.rules if r.action == "permit"]
        assert len(rules) >= 1
        # 第一条 permit 规则的源应含 object-group 展开后的地址
        first_permit = rules[0]
        assert len(first_permit.src_ip) >= 1

    def test_port_parsed(self, cisco_cfg):
        """端口 443 应正确解析到服务对象中。"""
        result = get_parser("cisco-asa").parse(cisco_cfg)
        all_services = [s for r in result.rules for s in r.services]
        dst_ports = [s.dst_port for s in all_services]
        # 至少有一个服务包含端口 443
        from fw_analyzer.models.port_range import PortRange
        assert any(p.contains(PortRange.single(443)) for p in dst_ports if not p.is_any())

    def test_deny_rule_exists(self, cisco_cfg):
        result = get_parser("cisco-asa").parse(cisco_cfg)
        assert any(r.action == "deny" for r in result.rules)


# ------------------------------------------------------------------
# Palo Alto 解析器
# ------------------------------------------------------------------

class TestPaloAltoParser:
    def test_parse_returns_result(self, paloalto_cfg):
        result = get_parser("paloalto").parse(paloalto_cfg, source_file="paloalto_simple.xml")
        assert isinstance(result, ParseResult)
        assert result.vendor == "paloalto"

    def test_rule_count(self, paloalto_cfg):
        result = get_parser("paloalto").parse(paloalto_cfg)
        assert result.rule_count >= 2

    def test_address_group_expanded(self, paloalto_cfg):
        """address-group internal-grp 应展开为 internal-net + dmz-net。"""
        result = get_parser("paloalto").parse(paloalto_cfg)
        # permit-https 规则引用了 internal-grp
        https_rules = [r for r in result.rules if "https" in r.rule_name.lower()]
        if https_rules:
            rule = https_rules[0]
            assert len(rule.src_ip) >= 2  # 至少展开出 2 个地址对象

    def test_zones_parsed(self, paloalto_cfg):
        result = get_parser("paloalto").parse(paloalto_cfg)
        rules_with_zone = [r for r in result.rules if r.src_zone or r.dst_zone]
        assert len(rules_with_zone) >= 1

    def test_rule_name(self, paloalto_cfg):
        result = get_parser("paloalto").parse(paloalto_cfg)
        names = {r.rule_name for r in result.rules}
        assert "permit-https" in names

    def test_disabled_rule_field(self, paloalto_cfg):
        result = get_parser("paloalto").parse(paloalto_cfg)
        # fixture 中所有规则都是 enabled
        assert all(r.enabled for r in result.rules)


# ------------------------------------------------------------------
# Fortinet 解析器
# ------------------------------------------------------------------

class TestFortinetParser:
    def test_parse_returns_result(self, fortinet_cfg):
        result = get_parser("fortinet").parse(fortinet_cfg, source_file="fortinet_simple.cfg")
        assert isinstance(result, ParseResult)
        assert result.vendor == "fortinet"

    def test_rule_count(self, fortinet_cfg):
        result = get_parser("fortinet").parse(fortinet_cfg)
        assert result.rule_count >= 2

    def test_permit_action(self, fortinet_cfg):
        result = get_parser("fortinet").parse(fortinet_cfg)
        permits = [r for r in result.rules if r.action == "permit"]
        assert len(permits) >= 1

    def test_address_group_expanded(self, fortinet_cfg):
        """addrgrp internal-grp 应展开为 internal-net + web-server。"""
        result = get_parser("fortinet").parse(fortinet_cfg)
        rules_with_grp = [r for r in result.rules if len(r.src_ip) >= 2]
        assert len(rules_with_grp) >= 1

    def test_service_port(self, fortinet_cfg):
        result = get_parser("fortinet").parse(fortinet_cfg)
        all_services = [s for r in result.rules for s in r.services]
        from fw_analyzer.models.port_range import PortRange
        assert any(
            s.protocol == "tcp" and s.dst_port.contains(PortRange.single(443))
            for s in all_services
        )


# ------------------------------------------------------------------
# get_parser 错误处理
# ------------------------------------------------------------------

class TestGetParser:
    def test_unknown_vendor_raises(self):
        with pytest.raises(ValueError, match="不支持的厂商"):
            get_parser("unknown-vendor")

    def test_case_insensitive(self):
        parser = get_parser("Huawei")
        assert parser is not None
