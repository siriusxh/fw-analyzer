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


# ==================================================================
# 复杂 fixture 测试（嵌套对象组、FQDN、禁用规则、非连续 wildcard）
# ==================================================================


class TestHuaweiComplex:
    """华为复杂配置：嵌套地址组 + ACL 非连续 wildcard + 禁用规则。"""

    def _parse(self, huawei_complex_cfg):
        return get_parser("huawei").parse(huawei_complex_cfg, source_file="huawei_complex.cfg")

    def test_parse_returns_result(self, huawei_complex_cfg):
        result = self._parse(huawei_complex_cfg)
        assert isinstance(result, ParseResult)
        assert result.vendor == "huawei"

    def test_security_policy_rule_count(self, huawei_complex_cfg):
        """新版安全策略应解析出 5 条规则。"""
        result = self._parse(huawei_complex_cfg)
        sp_rules = [r for r in result.rules if not r.raw_rule_id.startswith("acl")]
        assert len(sp_rules) == 5

    def test_acl_rule_count(self, huawei_complex_cfg):
        """ACL 应解析出 3 条规则。"""
        result = self._parse(huawei_complex_cfg)
        acl_rules = [r for r in result.rules if r.raw_rule_id.startswith("acl")]
        assert len(acl_rules) == 3

    def test_address_group_expanded(self, huawei_complex_cfg):
        """inner-grp 应展开为 2 个地址对象（10.1.1.1 + 10.1.1.2）。"""
        result = self._parse(huawei_complex_cfg)
        web_rule = [r for r in result.rules if r.rule_name == "permit-web"]
        assert len(web_rule) == 1
        src_values = [str(a.network) for a in web_rule[0].src_ip if a.network]
        assert "10.1.1.1/32" in src_values
        assert "10.1.1.2/32" in src_values

    def test_service_set_expanded(self, huawei_complex_cfg):
        """web-services service-set 应含 TCP 80-443。"""
        result = self._parse(huawei_complex_cfg)
        web_rule = [r for r in result.rules if r.rule_name == "permit-web"]
        assert len(web_rule) == 1
        svcs = web_rule[0].services
        assert len(svcs) >= 1
        # 应包含 tcp 端口 80 到 443
        from fw_analyzer.models.port_range import PortRange
        assert any(
            s.protocol == "tcp"
            and s.dst_port.contains(PortRange.single(80))
            and s.dst_port.contains(PortRange.single(443))
            for s in svcs
        )

    def test_db_service_set_expanded(self, huawei_complex_cfg):
        """db-services service-set 应含 TCP 3306 和 TCP 5432。"""
        result = self._parse(huawei_complex_cfg)
        db_rule = [r for r in result.rules if r.rule_name == "permit-db"]
        assert len(db_rule) == 1
        from fw_analyzer.models.port_range import PortRange
        svcs = db_rule[0].services
        ports = [(s.protocol, s.dst_port) for s in svcs]
        assert any(p == "tcp" and dp.contains(PortRange.single(3306)) for p, dp in ports)
        assert any(p == "tcp" and dp.contains(PortRange.single(5432)) for p, dp in ports)

    def test_disabled_rule(self, huawei_complex_cfg):
        """undo rule enable 应使规则 disabled。"""
        result = self._parse(huawei_complex_cfg)
        disabled = [r for r in result.rules if r.rule_name == "disabled-rule"]
        assert len(disabled) == 1
        assert disabled[0].enabled is False

    def test_zones_parsed(self, huawei_complex_cfg):
        """permit-web 应有 trust → untrust 域。"""
        result = self._parse(huawei_complex_cfg)
        web_rule = [r for r in result.rules if r.rule_name == "permit-web"][0]
        assert web_rule.src_zone == "trust"
        assert web_rule.dst_zone == "untrust"

    def test_acl_non_contiguous_wildcard_warning(self, huawei_complex_cfg):
        """ACL rule 1 使用非连续 wildcard 0.0.255.0，应产生 NON_CONTIGUOUS_WILDCARD 警告。"""
        result = self._parse(huawei_complex_cfg)
        all_warnings = []
        for r in result.rules:
            all_warnings.extend(r.warnings)
        all_warnings.extend(result.warnings)
        codes = [w.code for w in all_warnings]
        assert "NON_CONTIGUOUS_WILDCARD" in codes

    def test_acl_contiguous_wildcard_parsed(self, huawei_complex_cfg):
        """ACL rule 0 使用 0.0.0.255 wildcard，应正确解析为 192.168.1.0/24。"""
        result = self._parse(huawei_complex_cfg)
        acl_rule_0 = [r for r in result.rules if "rule0" in r.raw_rule_id]
        assert len(acl_rule_0) >= 1
        src_networks = [str(a.network) for a in acl_rule_0[0].src_ip if a.network]
        assert "192.168.1.0/24" in src_networks

    def test_deny_all_rule(self, huawei_complex_cfg):
        """deny-all 规则应存在。"""
        result = self._parse(huawei_complex_cfg)
        deny_all = [r for r in result.rules if r.rule_name == "deny-all"]
        assert len(deny_all) == 1
        assert deny_all[0].action == "deny"


class TestCiscoAsaComplex:
    """Cisco ASA 复杂配置：4层嵌套 + FQDN + 嵌套服务组。"""

    def _parse(self, cisco_complex_cfg):
        return get_parser("cisco-asa").parse(cisco_complex_cfg, source_file="cisco_asa_complex.cfg")

    def test_rule_count(self, cisco_complex_cfg):
        """应解析出 5 条 ACL 规则。"""
        result = self._parse(cisco_complex_cfg)
        assert result.rule_count == 5

    def test_deep_nesting_warning(self, cisco_complex_cfg):
        """deep-grp 为 4 层嵌套，应触发 DEEP_NESTING 警告。"""
        result = self._parse(cisco_complex_cfg)
        # 规则1 引用 deep-grp
        rule_0 = result.rules[0]
        all_warn_codes = [w.code for w in rule_0.warnings] + [w.code for w in result.warnings]
        assert "DEEP_NESTING" in all_warn_codes

    def test_deep_grp_expansion(self, cisco_complex_cfg):
        """deep-grp 展开后应包含 host-a(10.1.1.1), host-b(10.1.1.2), subnet-c(172.16.0.0/24), 192.168.0.0/16。"""
        result = self._parse(cisco_complex_cfg)
        rule_0 = result.rules[0]
        src_values = {str(a.network) for a in rule_0.src_ip if a.network}
        assert "10.1.1.1/32" in src_values
        assert "10.1.1.2/32" in src_values
        assert "172.16.0.0/24" in src_values
        assert "192.168.0.0/16" in src_values

    def test_fqdn_object_preserved(self, cisco_complex_cfg):
        """FQDN 对象应保留为 fqdn 类型，network=None。"""
        result = self._parse(cisco_complex_cfg)
        # 规则2 引用 fqdn-server
        rule_1 = result.rules[1]
        fqdn_addrs = [a for a in rule_1.dst_ip if a.type == "fqdn"]
        assert len(fqdn_addrs) >= 1
        assert fqdn_addrs[0].network is None
        assert "example.com" in fqdn_addrs[0].value

    def test_nested_service_group(self, cisco_complex_cfg):
        """admin-svcs 包含 web-svcs(80,443,8080-8443) + 22，应全部展开。"""
        result = self._parse(cisco_complex_cfg)
        # 规则3 引用 admin-svcs
        rule_2 = result.rules[2]
        from fw_analyzer.models.port_range import PortRange
        svcs = rule_2.services
        # 应包含端口 80, 443, 22, 以及 8080-8443 范围
        all_ports = svcs
        assert any(s.dst_port.contains(PortRange.single(80)) for s in all_ports)
        assert any(s.dst_port.contains(PortRange.single(443)) for s in all_ports)
        assert any(s.dst_port.contains(PortRange.single(22)) for s in all_ports)
        assert any(s.dst_port.contains(PortRange.single(8080)) for s in all_ports)

    def test_port_range_rule(self, cisco_complex_cfg):
        """规则4 端口范围 3306-3307 应正确解析。"""
        result = self._parse(cisco_complex_cfg)
        rule_3 = result.rules[3]
        from fw_analyzer.models.port_range import PortRange
        assert any(
            s.dst_port.contains(PortRange.single(3306))
            and s.dst_port.contains(PortRange.single(3307))
            for s in rule_3.services
        )

    def test_deny_all(self, cisco_complex_cfg):
        """最后一条规则应为 deny ip any any。"""
        result = self._parse(cisco_complex_cfg)
        last = result.rules[-1]
        assert last.action == "deny"


class TestPaloAltoComplex:
    """PAN-OS 复杂配置：嵌套 address-group + FQDN + ip-range + 禁用规则 + 服务组。"""

    def _parse(self, paloalto_complex_cfg):
        return get_parser("paloalto").parse(paloalto_complex_cfg, source_file="paloalto_complex.xml")

    def test_rule_count(self, paloalto_complex_cfg):
        """应解析出 5 条规则。"""
        result = self._parse(paloalto_complex_cfg)
        assert result.rule_count == 5

    def test_deep_nesting_warning(self, paloalto_complex_cfg):
        """deep-grp 为 4 层嵌套，应触发 DEEP_NESTING 警告。"""
        result = self._parse(paloalto_complex_cfg)
        rule_0 = [r for r in result.rules if r.rule_name == "permit-deep"][0]
        all_warn_codes = [w.code for w in rule_0.warnings]
        assert "DEEP_NESTING" in all_warn_codes

    def test_deep_grp_expansion(self, paloalto_complex_cfg):
        """deep-grp 展开应含 host-a, host-b, subnet-c, range-d。"""
        result = self._parse(paloalto_complex_cfg)
        rule_0 = [r for r in result.rules if r.rule_name == "permit-deep"][0]
        src_values = {a.value for a in rule_0.src_ip}
        assert "10.1.1.1/32" in src_values
        assert "10.1.1.2/32" in src_values
        assert "172.16.0.0/24" in src_values
        # ip-range 应保留为 range 类型
        range_addrs = [a for a in rule_0.src_ip if a.type == "range"]
        assert len(range_addrs) >= 1

    def test_fqdn_object(self, paloalto_complex_cfg):
        """fqdn-server 应保留为 fqdn 类型。"""
        result = self._parse(paloalto_complex_cfg)
        fqdn_rule = [r for r in result.rules if r.rule_name == "permit-fqdn"][0]
        fqdn_addrs = [a for a in fqdn_rule.dst_ip if a.type == "fqdn"]
        assert len(fqdn_addrs) >= 1
        assert "example.com" in fqdn_addrs[0].value

    def test_disabled_rule(self, paloalto_complex_cfg):
        """disabled-ssh 规则应为 enabled=False。"""
        result = self._parse(paloalto_complex_cfg)
        disabled = [r for r in result.rules if r.rule_name == "disabled-ssh"]
        assert len(disabled) == 1
        assert disabled[0].enabled is False

    def test_enabled_rule_count(self, paloalto_complex_cfg):
        """4 条 enabled + 1 条 disabled。"""
        result = self._parse(paloalto_complex_cfg)
        assert result.enabled_rule_count == 4

    def test_service_group_expanded(self, paloalto_complex_cfg):
        """web-svcs 服务组应展开为 svc-https(443) + svc-ssh(22)。"""
        result = self._parse(paloalto_complex_cfg)
        admin_rule = [r for r in result.rules if r.rule_name == "permit-admin"][0]
        from fw_analyzer.models.port_range import PortRange
        assert any(s.dst_port.contains(PortRange.single(443)) for s in admin_rule.services)
        assert any(s.dst_port.contains(PortRange.single(22)) for s in admin_rule.services)

    def test_zones(self, paloalto_complex_cfg):
        """permit-deep 应有 trust → untrust。"""
        result = self._parse(paloalto_complex_cfg)
        rule = [r for r in result.rules if r.rule_name == "permit-deep"][0]
        assert rule.src_zone == "trust"
        assert rule.dst_zone == "untrust"

    def test_deny_all(self, paloalto_complex_cfg):
        """deny-all 规则应为 drop/deny 动作。"""
        result = self._parse(paloalto_complex_cfg)
        deny_all = [r for r in result.rules if r.rule_name == "deny-all"][0]
        assert deny_all.action in ("deny", "drop")


class TestFortinetComplex:
    """Fortinet 复杂配置：嵌套 addrgrp + FQDN + wildcard-fqdn + 禁用规则 + 服务组。"""

    def _parse(self, fortinet_complex_cfg):
        return get_parser("fortinet").parse(fortinet_complex_cfg, source_file="fortinet_complex.cfg")

    def _find_rule(self, result, name_substring):
        """按 rule_name 子串查找规则（兼容引号包裹情况）。"""
        for r in result.rules:
            if name_substring in r.rule_name:
                return r
        return None

    def test_rule_count(self, fortinet_complex_cfg):
        """应解析出 6 条规则。"""
        result = self._parse(fortinet_complex_cfg)
        assert result.rule_count == 6

    def test_deep_nesting_warning(self, fortinet_complex_cfg):
        """deep-grp 为 4 层嵌套，应触发 DEEP_NESTING 警告。"""
        result = self._parse(fortinet_complex_cfg)
        rule_0 = self._find_rule(result, "permit-deep")
        assert rule_0 is not None
        all_warn_codes = [w.code for w in rule_0.warnings]
        assert "DEEP_NESTING" in all_warn_codes

    def test_deep_grp_expansion(self, fortinet_complex_cfg):
        """deep-grp 展开后应包含 host-a, host-b, subnet-c, net-192。"""
        result = self._parse(fortinet_complex_cfg)
        rule_0 = self._find_rule(result, "permit-deep")
        assert rule_0 is not None
        src_values = {a.value for a in rule_0.src_ip}
        assert "10.1.1.1/32" in src_values
        assert "10.1.1.2/32" in src_values
        assert "172.16.0.0/24" in src_values
        assert "192.168.0.0/16" in src_values

    def test_fqdn_object(self, fortinet_complex_cfg):
        """fqdn-server 应保留为 fqdn 类型。"""
        result = self._parse(fortinet_complex_cfg)
        fqdn_rule = self._find_rule(result, "permit-fqdn")
        assert fqdn_rule is not None
        fqdn_addrs = [a for a in fqdn_rule.dst_ip if a.type == "fqdn"]
        assert len(fqdn_addrs) >= 1

    def test_wildcard_fqdn(self, fortinet_complex_cfg):
        """wildcard-fqdn 类型对象应作为 fqdn 类型处理。"""
        result = self._parse(fortinet_complex_cfg)
        wfqdn_rule = self._find_rule(result, "permit-wildcard-fqdn")
        assert wfqdn_rule is not None
        fqdn_addrs = [a for a in wfqdn_rule.dst_ip if a.type == "fqdn"]
        assert len(fqdn_addrs) >= 1
        assert "example.org" in fqdn_addrs[0].value

    def test_disabled_rule(self, fortinet_complex_cfg):
        """disabled-ssh 规则应为 enabled=False。"""
        result = self._parse(fortinet_complex_cfg)
        disabled = self._find_rule(result, "disabled-ssh")
        assert disabled is not None
        assert disabled.enabled is False

    def test_enabled_rule_count(self, fortinet_complex_cfg):
        """5 条 enabled + 1 条 disabled。"""
        result = self._parse(fortinet_complex_cfg)
        assert result.enabled_rule_count == 5

    def test_service_group_expanded(self, fortinet_complex_cfg):
        """web-svcs 服务组应展开为 HTTPS(443) + SSH(22)。"""
        result = self._parse(fortinet_complex_cfg)
        admin_rule = self._find_rule(result, "permit-admin")
        assert admin_rule is not None
        from fw_analyzer.models.port_range import PortRange
        assert any(
            s.protocol == "tcp" and s.dst_port.contains(PortRange.single(443))
            for s in admin_rule.services
        )
        assert any(
            s.protocol == "tcp" and s.dst_port.contains(PortRange.single(22))
            for s in admin_rule.services
        )

    def test_zones(self, fortinet_complex_cfg):
        """permit-deep 应有 lan → wan。"""
        result = self._parse(fortinet_complex_cfg)
        rule = self._find_rule(result, "permit-deep")
        assert rule is not None
        assert "lan" in rule.src_zone
        assert "wan" in rule.dst_zone

    def test_deny_all(self, fortinet_complex_cfg):
        """deny-all 规则应存在。"""
        result = self._parse(fortinet_complex_cfg)
        deny_all = self._find_rule(result, "deny-all")
        assert deny_all is not None
        assert deny_all.action in ("deny", "drop")


# ==================================================================
# PAN-OS set 命令格式解析器测试
# ==================================================================


class TestPaloAltoSetParser:
    """PAN-OS set 命令格式基础测试。"""

    def test_parse_returns_result(self, paloalto_set_cfg):
        result = get_parser("paloalto-set").parse(paloalto_set_cfg, source_file="paloalto_set_simple.cfg")
        assert isinstance(result, ParseResult)
        assert result.vendor == "paloalto"

    def test_rule_count(self, paloalto_set_cfg):
        result = get_parser("paloalto-set").parse(paloalto_set_cfg)
        assert result.rule_count == 3

    def test_address_group_expanded(self, paloalto_set_cfg):
        """address-group internal-grp 应展开为 internal-net + dmz-net。"""
        result = get_parser("paloalto-set").parse(paloalto_set_cfg)
        https_rules = [r for r in result.rules if "https" in r.rule_name.lower()]
        assert len(https_rules) >= 1
        rule = https_rules[0]
        assert len(rule.src_ip) >= 2

    def test_zones_parsed(self, paloalto_set_cfg):
        result = get_parser("paloalto-set").parse(paloalto_set_cfg)
        rules_with_zone = [r for r in result.rules if r.src_zone or r.dst_zone]
        assert len(rules_with_zone) >= 1

    def test_rule_name(self, paloalto_set_cfg):
        result = get_parser("paloalto-set").parse(paloalto_set_cfg)
        names = {r.rule_name for r in result.rules}
        assert "permit-https" in names

    def test_disabled_rule_field(self, paloalto_set_cfg):
        """simple fixture 中所有规则都是 enabled。"""
        result = get_parser("paloalto-set").parse(paloalto_set_cfg)
        assert all(r.enabled for r in result.rules)

    def test_service_parsed(self, paloalto_set_cfg):
        result = get_parser("paloalto-set").parse(paloalto_set_cfg)
        from fw_analyzer.models.port_range import PortRange
        all_services = [s for r in result.rules for s in r.services]
        assert any(
            s.protocol == "tcp" and s.dst_port.contains(PortRange.single(443))
            for s in all_services
        )

    def test_detect_vendor(self, paloalto_set_cfg):
        """detect_vendor 应识别为 paloalto-set。"""
        assert detect_vendor(paloalto_set_cfg) == "paloalto-set"


class TestPaloAltoSetComplex:
    """PAN-OS set 命令格式复杂配置：嵌套组 + FQDN + IP字面量 + 引号名称 + 服务组。"""

    def _parse(self, paloalto_set_complex_cfg):
        return get_parser("paloalto-set").parse(
            paloalto_set_complex_cfg, source_file="paloalto_set_complex.cfg"
        )

    def test_rule_count(self, paloalto_set_complex_cfg):
        """应解析出 7 条规则。"""
        result = self._parse(paloalto_set_complex_cfg)
        assert result.rule_count == 7

    def test_deep_nesting_warning(self, paloalto_set_complex_cfg):
        """deep-grp 为 4 层嵌套，应触发 DEEP_NESTING 警告。"""
        result = self._parse(paloalto_set_complex_cfg)
        rule_0 = [r for r in result.rules if r.rule_name == "permit-deep"][0]
        all_warn_codes = [w.code for w in rule_0.warnings]
        assert "DEEP_NESTING" in all_warn_codes

    def test_deep_grp_expansion(self, paloalto_set_complex_cfg):
        """deep-grp 展开应含 host-a, host-b, subnet-c, range-d。"""
        result = self._parse(paloalto_set_complex_cfg)
        rule_0 = [r for r in result.rules if r.rule_name == "permit-deep"][0]
        src_values = {a.value for a in rule_0.src_ip}
        assert "10.1.1.1/32" in src_values
        assert "10.1.1.2/32" in src_values
        assert "172.16.0.0/24" in src_values
        range_addrs = [a for a in rule_0.src_ip if a.type == "range"]
        assert len(range_addrs) >= 1

    def test_fqdn_object(self, paloalto_set_complex_cfg):
        """fqdn-server 应保留为 fqdn 类型。"""
        result = self._parse(paloalto_set_complex_cfg)
        fqdn_rule = [r for r in result.rules if r.rule_name == "permit-fqdn"][0]
        fqdn_addrs = [a for a in fqdn_rule.dst_ip if a.type == "fqdn"]
        assert len(fqdn_addrs) >= 1
        assert "example.com" in fqdn_addrs[0].value

    def test_disabled_rule(self, paloalto_set_complex_cfg):
        """disabled-ssh 规则应为 enabled=False。"""
        result = self._parse(paloalto_set_complex_cfg)
        disabled = [r for r in result.rules if r.rule_name == "disabled-ssh"]
        assert len(disabled) == 1
        assert disabled[0].enabled is False

    def test_enabled_rule_count(self, paloalto_set_complex_cfg):
        """6 条 enabled + 1 条 disabled。"""
        result = self._parse(paloalto_set_complex_cfg)
        assert result.enabled_rule_count == 6

    def test_service_group_expanded(self, paloalto_set_complex_cfg):
        """web-svcs 服务组应展开为 svc-https(443) + svc-ssh(22)。"""
        result = self._parse(paloalto_set_complex_cfg)
        admin_rule = [r for r in result.rules if r.rule_name == "permit-admin"][0]
        from fw_analyzer.models.port_range import PortRange
        assert any(s.dst_port.contains(PortRange.single(443)) for s in admin_rule.services)
        assert any(s.dst_port.contains(PortRange.single(22)) for s in admin_rule.services)

    def test_zones(self, paloalto_set_complex_cfg):
        """permit-deep 应有 trust → untrust。"""
        result = self._parse(paloalto_set_complex_cfg)
        rule = [r for r in result.rules if r.rule_name == "permit-deep"][0]
        assert rule.src_zone == "trust"
        assert rule.dst_zone == "untrust"

    def test_deny_all(self, paloalto_set_complex_cfg):
        """deny-all 规则应为 drop/deny 动作。"""
        result = self._parse(paloalto_set_complex_cfg)
        deny_all = [r for r in result.rules if r.rule_name == "deny-all"][0]
        assert deny_all.action in ("deny", "drop")

    def test_inline_ip_literals(self, paloalto_set_complex_cfg):
        """permit-inline-ip 规则中的 IP 字面量应被正确解析，无 UNRESOLVED 警告。"""
        result = self._parse(paloalto_set_complex_cfg)
        rule = [r for r in result.rules if r.rule_name == "permit-inline-ip"][0]
        # 不应有 UNRESOLVED_OBJECT 警告
        unresolved = [w for w in rule.warnings if w.code == "UNRESOLVED_OBJECT"]
        assert len(unresolved) == 0
        # 源地址：10.99.0.1/32 + 10.99.0.0/24
        src_values = {a.value for a in rule.src_ip}
        assert "10.99.0.1/32" in src_values
        assert "10.99.0.0/24" in src_values
        # 目的地址：203.0.113.50/32
        dst_values = {a.value for a in rule.dst_ip}
        assert "203.0.113.50/32" in dst_values

    def test_quoted_name_address(self, paloalto_set_complex_cfg):
        """带引号空格的地址名 'tm- 188.172.203.62' 应正确解析。"""
        result = self._parse(paloalto_set_complex_cfg)
        rule = [r for r in result.rules if r.rule_name == "Deny Quoted"][0]
        dst_values = {a.value for a in rule.dst_ip}
        assert "188.172.203.62/32" in dst_values

    def test_quoted_name_service(self, paloalto_set_complex_cfg):
        """带引号空格的服务名 'TCP 8080-8090' 应正确解析端口范围。"""
        result = self._parse(paloalto_set_complex_cfg)
        rule = [r for r in result.rules if r.rule_name == "Deny Quoted"][0]
        from fw_analyzer.models.port_range import PortRange
        assert any(
            s.protocol == "tcp"
            and s.dst_port.contains(PortRange.single(8080))
            and s.dst_port.contains(PortRange.single(8090))
            for s in rule.services
        )

    def test_description(self, paloalto_set_complex_cfg):
        """permit-deep 规则应有描述。"""
        result = self._parse(paloalto_set_complex_cfg)
        rule = [r for r in result.rules if r.rule_name == "permit-deep"][0]
        assert "HTTPS" in rule.comment or "deep" in rule.comment.lower()

    def test_no_warnings_on_named_objects(self, paloalto_set_complex_cfg):
        """使用命名对象的规则不应有 UNRESOLVED 警告。"""
        result = self._parse(paloalto_set_complex_cfg)
        for rule in result.rules:
            if rule.rule_name in ("permit-deep", "permit-fqdn", "permit-admin",
                                   "disabled-ssh", "Deny Quoted", "deny-all"):
                unresolved = [w for w in rule.warnings if w.code == "UNRESOLVED_OBJECT"]
                assert len(unresolved) == 0, f"{rule.rule_name} has unresolved: {unresolved}"


# ==================================================================
# Parser-level log_enabled 测试（内联配置字符串）
# ==================================================================


class TestHuaweiLogEnabled:
    """华为解析器 log_enabled 字段提取测试。"""

    SECURITY_POLICY_WITH_LOG = """\
security-policy
 rule name rule-with-log
  source-zone trust
  destination-zone untrust
  source-address any
  destination-address any
  service any
  action permit
  policy logging
 rule name rule-with-session-log
  source-zone trust
  destination-zone untrust
  source-address any
  destination-address any
  service any
  action permit
  session logging
 rule name rule-with-traffic-log
  source-zone trust
  destination-zone untrust
  source-address any
  destination-address any
  service any
  action permit
  traffic logging
 rule name rule-no-log
  source-zone trust
  destination-zone untrust
  source-address any
  destination-address any
  service any
  action deny
"""

    def test_policy_logging_detected(self):
        result = get_parser("huawei").parse(self.SECURITY_POLICY_WITH_LOG)
        rule = [r for r in result.rules if r.rule_name == "rule-with-log"][0]
        assert rule.log_enabled is True

    def test_session_logging_detected(self):
        result = get_parser("huawei").parse(self.SECURITY_POLICY_WITH_LOG)
        rule = [r for r in result.rules if r.rule_name == "rule-with-session-log"][0]
        assert rule.log_enabled is True

    def test_traffic_logging_detected(self):
        result = get_parser("huawei").parse(self.SECURITY_POLICY_WITH_LOG)
        rule = [r for r in result.rules if r.rule_name == "rule-with-traffic-log"][0]
        assert rule.log_enabled is True

    def test_no_logging_detected(self):
        result = get_parser("huawei").parse(self.SECURITY_POLICY_WITH_LOG)
        rule = [r for r in result.rules if r.rule_name == "rule-no-log"][0]
        assert rule.log_enabled is False

    ACL_WITH_LOG = """\
acl number 3000
 rule 0 permit ip source 10.0.0.0 0.0.0.255 logging
 rule 1 deny ip source 10.1.0.0 0.0.255.255
"""

    def test_acl_logging_keyword_detected(self):
        result = get_parser("huawei").parse(self.ACL_WITH_LOG)
        acl_rules = [r for r in result.rules if r.raw_rule_id.startswith("acl")]
        rule_0 = [r for r in acl_rules if "rule0" in r.raw_rule_id][0]
        assert rule_0.log_enabled is True

    def test_acl_no_logging_keyword(self):
        result = get_parser("huawei").parse(self.ACL_WITH_LOG)
        acl_rules = [r for r in result.rules if r.raw_rule_id.startswith("acl")]
        rule_1 = [r for r in acl_rules if "rule1" in r.raw_rule_id][0]
        assert rule_1.log_enabled is False


class TestCiscoAsaLogEnabled:
    """Cisco ASA 解析器 log_enabled 字段提取测试。"""

    CISCO_ACL_WITH_LOG = """\
access-list outside extended permit tcp any any eq 443 log
access-list outside extended permit tcp any any eq 80 log warnings
access-list outside extended deny ip any any
"""

    def test_log_keyword_detected(self):
        result = get_parser("cisco-asa").parse(self.CISCO_ACL_WITH_LOG)
        rule_0 = result.rules[0]
        assert rule_0.log_enabled is True

    def test_log_with_level_detected(self):
        result = get_parser("cisco-asa").parse(self.CISCO_ACL_WITH_LOG)
        rule_1 = result.rules[1]
        assert rule_1.log_enabled is True

    def test_no_log_keyword(self):
        result = get_parser("cisco-asa").parse(self.CISCO_ACL_WITH_LOG)
        rule_2 = result.rules[2]
        assert rule_2.log_enabled is False

    def test_log_does_not_affect_service_parsing(self):
        """确保剥离 log 关键字后端口解析不受影响。"""
        result = get_parser("cisco-asa").parse(self.CISCO_ACL_WITH_LOG)
        from fw_analyzer.models.port_range import PortRange
        rule_0 = result.rules[0]
        assert any(
            s.dst_port.contains(PortRange.single(443)) for s in rule_0.services
        )
        rule_1 = result.rules[1]
        assert any(
            s.dst_port.contains(PortRange.single(80)) for s in rule_1.services
        )


class TestFortinetLogEnabled:
    """Fortinet 解析器 log_enabled 字段提取测试。"""

    FORTINET_POLICY_WITH_LOG = """\
config firewall policy
    edit 1
        set name "permit-web-logged"
        set srcintf "inside"
        set dstintf "outside"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
        set logtraffic all
    next
    edit 2
        set name "permit-web-utm"
        set srcintf "inside"
        set dstintf "outside"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
        set logtraffic utm
    next
    edit 3
        set name "deny-no-log"
        set srcintf "inside"
        set dstintf "outside"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action deny
        set logtraffic disable
    next
    edit 4
        set name "deny-default"
        set srcintf "inside"
        set dstintf "outside"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action deny
    next
end
"""

    def _find_rule(self, result, name_substring):
        for r in result.rules:
            if name_substring in r.rule_name:
                return r
        return None

    def test_logtraffic_all(self):
        result = get_parser("fortinet").parse(self.FORTINET_POLICY_WITH_LOG)
        rule = self._find_rule(result, "permit-web-logged")
        assert rule is not None
        assert rule.log_enabled is True

    def test_logtraffic_utm(self):
        result = get_parser("fortinet").parse(self.FORTINET_POLICY_WITH_LOG)
        rule = self._find_rule(result, "permit-web-utm")
        assert rule is not None
        assert rule.log_enabled is True

    def test_logtraffic_disable(self):
        result = get_parser("fortinet").parse(self.FORTINET_POLICY_WITH_LOG)
        rule = self._find_rule(result, "deny-no-log")
        assert rule is not None
        assert rule.log_enabled is False

    def test_logtraffic_missing(self):
        """未设置 logtraffic 的策略应为 log_enabled=False。"""
        result = get_parser("fortinet").parse(self.FORTINET_POLICY_WITH_LOG)
        rule = self._find_rule(result, "deny-default")
        assert rule is not None
        assert rule.log_enabled is False


class TestPaloAltoSetLogEnabled:
    """PAN-OS set 格式解析器 log_enabled 字段提取测试。"""

    PA_SET_WITH_LOG = """\
set rulebase security rules rule-with-log-setting from any
set rulebase security rules rule-with-log-setting to any
set rulebase security rules rule-with-log-setting source any
set rulebase security rules rule-with-log-setting destination any
set rulebase security rules rule-with-log-setting service any
set rulebase security rules rule-with-log-setting action allow
set rulebase security rules rule-with-log-setting log-setting default
set rulebase security rules rule-with-log-end from any
set rulebase security rules rule-with-log-end to any
set rulebase security rules rule-with-log-end source any
set rulebase security rules rule-with-log-end destination any
set rulebase security rules rule-with-log-end service any
set rulebase security rules rule-with-log-end action allow
set rulebase security rules rule-with-log-end log-end yes
set rulebase security rules rule-with-log-start from any
set rulebase security rules rule-with-log-start to any
set rulebase security rules rule-with-log-start source any
set rulebase security rules rule-with-log-start destination any
set rulebase security rules rule-with-log-start service any
set rulebase security rules rule-with-log-start action allow
set rulebase security rules rule-with-log-start log-start yes
set rulebase security rules rule-no-log from any
set rulebase security rules rule-no-log to any
set rulebase security rules rule-no-log source any
set rulebase security rules rule-no-log destination any
set rulebase security rules rule-no-log service any
set rulebase security rules rule-no-log action deny
"""

    def test_log_setting_detected(self):
        result = get_parser("paloalto-set").parse(self.PA_SET_WITH_LOG)
        rule = [r for r in result.rules if r.rule_name == "rule-with-log-setting"][0]
        assert rule.log_enabled is True

    def test_log_end_detected(self):
        result = get_parser("paloalto-set").parse(self.PA_SET_WITH_LOG)
        rule = [r for r in result.rules if r.rule_name == "rule-with-log-end"][0]
        assert rule.log_enabled is True

    def test_log_start_detected(self):
        result = get_parser("paloalto-set").parse(self.PA_SET_WITH_LOG)
        rule = [r for r in result.rules if r.rule_name == "rule-with-log-start"][0]
        assert rule.log_enabled is True

    def test_no_log_props(self):
        result = get_parser("paloalto-set").parse(self.PA_SET_WITH_LOG)
        rule = [r for r in result.rules if r.rule_name == "rule-no-log"][0]
        assert rule.log_enabled is False


# ------------------------------------------------------------------
# PA set 格式 application→protocol 映射测试
# ------------------------------------------------------------------

class TestPaloAltoSetAppMapping:
    """PAN-OS set 格式 application-default + 具体 application 映射测试。"""

    PA_SET_APP_ICMP = """\
set rulebase security rules icmp-rule from trust
set rulebase security rules icmp-rule to untrust
set rulebase security rules icmp-rule source any
set rulebase security rules icmp-rule destination any
set rulebase security rules icmp-rule application [ icmp ping traceroute ]
set rulebase security rules icmp-rule service application-default
set rulebase security rules icmp-rule action allow
set rulebase security rules icmp-rule log-setting default
"""

    PA_SET_APP_NTP = """\
set rulebase security rules ntp-rule from trust
set rulebase security rules ntp-rule to untrust
set rulebase security rules ntp-rule source any
set rulebase security rules ntp-rule destination any
set rulebase security rules ntp-rule application ntp
set rulebase security rules ntp-rule service application-default
set rulebase security rules ntp-rule action allow
set rulebase security rules ntp-rule log-setting default
"""

    PA_SET_APP_ANY = """\
set rulebase security rules any-app-rule from trust
set rulebase security rules any-app-rule to untrust
set rulebase security rules any-app-rule source any
set rulebase security rules any-app-rule destination any
set rulebase security rules any-app-rule application any
set rulebase security rules any-app-rule service application-default
set rulebase security rules any-app-rule action allow
set rulebase security rules any-app-rule log-setting default
"""

    PA_SET_APP_UNKNOWN = """\
set rulebase security rules unknown-app-rule from trust
set rulebase security rules unknown-app-rule to untrust
set rulebase security rules unknown-app-rule source any
set rulebase security rules unknown-app-rule destination any
set rulebase security rules unknown-app-rule application some-unknown-app
set rulebase security rules unknown-app-rule service application-default
set rulebase security rules unknown-app-rule action allow
set rulebase security rules unknown-app-rule log-setting default
"""

    PA_SET_APP_EXPLICIT_SVC = """\
set service my-svc protocol tcp port 8080
set rulebase security rules explicit-svc-rule from trust
set rulebase security rules explicit-svc-rule to untrust
set rulebase security rules explicit-svc-rule source any
set rulebase security rules explicit-svc-rule destination any
set rulebase security rules explicit-svc-rule application [ icmp ping ]
set rulebase security rules explicit-svc-rule service my-svc
set rulebase security rules explicit-svc-rule action allow
set rulebase security rules explicit-svc-rule log-setting default
"""

    PA_SET_APP_DNS = """\
set rulebase security rules dns-rule from trust
set rulebase security rules dns-rule to untrust
set rulebase security rules dns-rule source any
set rulebase security rules dns-rule destination any
set rulebase security rules dns-rule application dns
set rulebase security rules dns-rule service application-default
set rulebase security rules dns-rule action allow
set rulebase security rules dns-rule log-setting default
"""

    PA_SET_APP_MIXED = """\
set rulebase security rules mixed-rule from trust
set rulebase security rules mixed-rule to untrust
set rulebase security rules mixed-rule source any
set rulebase security rules mixed-rule destination any
set rulebase security rules mixed-rule application [ icmp some-custom-app ]
set rulebase security rules mixed-rule service application-default
set rulebase security rules mixed-rule action allow
set rulebase security rules mixed-rule log-setting default
"""

    def test_icmp_apps_mapped_to_icmp_protocol(self):
        """icmp + ping + traceroute → icmp 协议。"""
        result = get_parser("paloalto-set").parse(self.PA_SET_APP_ICMP)
        rule = result.rules[0]
        assert len(rule.services) > 0
        assert all(s.protocol == "icmp" for s in rule.services)

    def test_icmp_apps_deduped(self):
        """icmp, ping, traceroute 都映射到 icmp/0-0，去重后只有一个。"""
        result = get_parser("paloalto-set").parse(self.PA_SET_APP_ICMP)
        rule = result.rules[0]
        assert len(rule.services) == 1
        assert rule.services[0].protocol == "icmp"

    def test_ntp_mapped_to_udp_123(self):
        """ntp → udp/123。"""
        result = get_parser("paloalto-set").parse(self.PA_SET_APP_NTP)
        rule = result.rules[0]
        assert len(rule.services) == 1
        assert rule.services[0].protocol == "udp"
        assert rule.services[0].dst_port.low == 123
        assert rule.services[0].dst_port.high == 123

    def test_app_any_stays_any(self):
        """application=any + service=application-default → services 为空（any）。"""
        result = get_parser("paloalto-set").parse(self.PA_SET_APP_ANY)
        rule = result.rules[0]
        assert rule.services == []
        assert rule.service_str() == "any"

    def test_unknown_app_falls_back_to_any(self):
        """未知 application → services 为空（any）。"""
        result = get_parser("paloalto-set").parse(self.PA_SET_APP_UNKNOWN)
        rule = result.rules[0]
        assert rule.services == []

    def test_explicit_service_ignores_application(self):
        """当 service 指定了具体服务名，application 不影响服务解析。"""
        result = get_parser("paloalto-set").parse(self.PA_SET_APP_EXPLICIT_SVC)
        rule = result.rules[0]
        assert len(rule.services) == 1
        assert rule.services[0].protocol == "tcp"
        assert rule.services[0].dst_port.low == 8080

    def test_dns_mapped_to_udp_tcp_53(self):
        """dns → udp/53 + tcp/53。"""
        result = get_parser("paloalto-set").parse(self.PA_SET_APP_DNS)
        rule = result.rules[0]
        assert len(rule.services) == 2
        protocols = {s.protocol for s in rule.services}
        assert protocols == {"udp", "tcp"}
        for s in rule.services:
            assert s.dst_port.low == 53

    def test_mixed_known_unknown_falls_back_to_any(self):
        """一个已知 + 一个未知 application → 回退到 any。"""
        result = get_parser("paloalto-set").parse(self.PA_SET_APP_MIXED)
        rule = result.rules[0]
        assert rule.services == []


# ==================================================================
# PAN-OS URL 分类（category）字段解析测试
# ==================================================================


class TestPaloAltoSetUrlCategory:
    """PAN-OS set 格式 URL 分类解析测试。"""

    PA_SET_WITH_CATEGORY = """\
set rulebase security rules cat-rule from trust
set rulebase security rules cat-rule to untrust
set rulebase security rules cat-rule source any
set rulebase security rules cat-rule destination any
set rulebase security rules cat-rule service any
set rulebase security rules cat-rule action allow
set rulebase security rules cat-rule category [ adult malware ]
"""

    PA_SET_CATEGORY_ANY = """\
set rulebase security rules cat-any-rule from trust
set rulebase security rules cat-any-rule to untrust
set rulebase security rules cat-any-rule source any
set rulebase security rules cat-any-rule destination any
set rulebase security rules cat-any-rule service any
set rulebase security rules cat-any-rule action allow
set rulebase security rules cat-any-rule category any
"""

    PA_SET_NO_CATEGORY = """\
set rulebase security rules no-cat-rule from trust
set rulebase security rules no-cat-rule to untrust
set rulebase security rules no-cat-rule source any
set rulebase security rules no-cat-rule destination any
set rulebase security rules no-cat-rule service any
set rulebase security rules no-cat-rule action allow
"""

    PA_SET_SINGLE_CATEGORY = """\
set rulebase security rules single-cat-rule from trust
set rulebase security rules single-cat-rule to untrust
set rulebase security rules single-cat-rule source any
set rulebase security rules single-cat-rule destination any
set rulebase security rules single-cat-rule service any
set rulebase security rules single-cat-rule action deny
set rulebase security rules single-cat-rule category streaming
"""

    def test_multiple_categories_parsed(self):
        """多个 URL 分类用分号拼接。"""
        result = get_parser("paloalto-set").parse(self.PA_SET_WITH_CATEGORY)
        rule = result.rules[0]
        assert rule.url_category == "adult; malware"

    def test_category_any_treated_as_empty(self):
        """category=any → url_category 为空。"""
        result = get_parser("paloalto-set").parse(self.PA_SET_CATEGORY_ANY)
        rule = result.rules[0]
        assert rule.url_category == ""

    def test_no_category_field_treated_as_empty(self):
        """无 category 属性 → url_category 为空。"""
        result = get_parser("paloalto-set").parse(self.PA_SET_NO_CATEGORY)
        rule = result.rules[0]
        assert rule.url_category == ""

    def test_single_category_parsed(self):
        """单个非 any 分类被正确解析。"""
        result = get_parser("paloalto-set").parse(self.PA_SET_SINGLE_CATEGORY)
        rule = result.rules[0]
        assert rule.url_category == "streaming"


class TestPaloAltoXmlUrlCategory:
    """PAN-OS XML 格式 URL 分类解析测试。"""

    PA_XML_WITH_CATEGORY = """\
<config>
  <devices><entry><vsys><entry>
    <rulebase><security><rules>
      <entry name="cat-rule">
        <from><member>trust</member></from>
        <to><member>untrust</member></to>
        <source><member>any</member></source>
        <destination><member>any</member></destination>
        <service><member>any</member></service>
        <action>allow</action>
        <category>
          <member>adult</member>
          <member>malware</member>
        </category>
      </entry>
    </rules></security></rulebase>
  </entry></vsys></entry></devices>
</config>
"""

    PA_XML_CATEGORY_ANY = """\
<config>
  <devices><entry><vsys><entry>
    <rulebase><security><rules>
      <entry name="cat-any-rule">
        <from><member>trust</member></from>
        <to><member>untrust</member></to>
        <source><member>any</member></source>
        <destination><member>any</member></destination>
        <service><member>any</member></service>
        <action>allow</action>
        <category>
          <member>any</member>
        </category>
      </entry>
    </rules></security></rulebase>
  </entry></vsys></entry></devices>
</config>
"""

    PA_XML_NO_CATEGORY = """\
<config>
  <devices><entry><vsys><entry>
    <rulebase><security><rules>
      <entry name="no-cat-rule">
        <from><member>trust</member></from>
        <to><member>untrust</member></to>
        <source><member>any</member></source>
        <destination><member>any</member></destination>
        <service><member>any</member></service>
        <action>allow</action>
      </entry>
    </rules></security></rulebase>
  </entry></vsys></entry></devices>
</config>
"""

    def test_xml_multiple_categories_parsed(self):
        """XML 多个 URL 分类用分号拼接。"""
        result = get_parser("paloalto").parse(self.PA_XML_WITH_CATEGORY)
        rule = result.rules[0]
        assert rule.url_category == "adult; malware"

    def test_xml_category_any_treated_as_empty(self):
        """XML category=any → url_category 为空。"""
        result = get_parser("paloalto").parse(self.PA_XML_CATEGORY_ANY)
        rule = result.rules[0]
        assert rule.url_category == ""

    def test_xml_no_category_treated_as_empty(self):
        """XML 无 category 元素 → url_category 为空。"""
        result = get_parser("paloalto").parse(self.PA_XML_NO_CATEGORY)
        rule = result.rules[0]
        assert rule.url_category == ""


# ------------------------------------------------------------------
# Cisco ASA 未知协议解析
# ------------------------------------------------------------------

class TestCiscoAsaUnknownProtocol:
    """Cisco ASA 未知协议名应正确消费 token，不污染地址解析。"""

    CISCO_UNKNOWN_PROTO = """\
access-list outside extended permit ipinip host 10.1.1.1 host 10.2.2.2 log
access-list outside extended permit pim host 10.3.3.3 host 10.4.4.4
access-list outside extended permit tcp host 10.5.5.5 host 10.6.6.6 eq 443
access-list outside extended deny ip any any
"""

    def _parse(self):
        return get_parser("cisco-asa").parse(self.CISCO_UNKNOWN_PROTO)

    def test_ipinip_protocol_parsed(self):
        """ipinip 应识别为协议名而非地址。"""
        result = self._parse()
        rule = result.rules[0]
        assert len(rule.services) == 1
        assert rule.services[0].protocol == "ipinip"

    def test_ipinip_src_parsed(self):
        """ipinip 规则的源地址应为 10.1.1.1/32。"""
        from ipaddress import IPv4Network
        result = self._parse()
        rule = result.rules[0]
        src_nets = {str(a.network) for a in rule.src_ip if a.network}
        assert "10.1.1.1/32" in src_nets

    def test_ipinip_dst_parsed(self):
        """ipinip 规则的目的地址应为 10.2.2.2/32。"""
        result = self._parse()
        rule = result.rules[0]
        dst_nets = {str(a.network) for a in rule.dst_ip if a.network}
        assert "10.2.2.2/32" in dst_nets

    def test_pim_protocol_parsed(self):
        """pim 作为另一种未知协议也应正确解析。"""
        result = self._parse()
        rule = result.rules[1]
        assert rule.services[0].protocol == "pim"
        src_nets = {str(a.network) for a in rule.src_ip if a.network}
        assert "10.3.3.3/32" in src_nets

    def test_known_proto_still_works(self):
        """已知协议 tcp 仍应正常解析（回归保护）。"""
        from fw_analyzer.models.port_range import PortRange
        result = self._parse()
        rule = result.rules[2]
        assert rule.services[0].protocol == "tcp"
        assert any(s.dst_port.contains(PortRange.single(443)) for s in rule.services)

    def test_deny_all_still_works(self):
        """deny ip any any 仍应正常解析。"""
        result = self._parse()
        last = result.rules[-1]
        assert last.action == "deny"
        assert last.services[0].protocol == "any"  # ip → any


# ------------------------------------------------------------------
# 华为 ACL 未知协议解析
# ------------------------------------------------------------------

class TestHuaweiUnknownProtocol:
    """华为 ACL 未知协议名应正确消费 token，不污染地址解析。"""

    HUAWEI_UNKNOWN_PROTO = """\
acl number 3100
 rule 0 permit esp source 10.0.0.0 0.0.0.255
 rule 1 permit ah source 10.1.0.0 0.0.255.255 destination 10.2.0.0 0.0.255.255
 rule 2 permit tcp source 10.3.0.0 0.0.0.255 destination-port eq 22
 rule 3 permit ipinip source 10.4.0.0 0.0.0.255
"""

    def _parse(self):
        return get_parser("huawei").parse(self.HUAWEI_UNKNOWN_PROTO)

    def test_esp_protocol_parsed(self):
        """esp 应识别为协议名。"""
        result = self._parse()
        acl_rules = [r for r in result.rules if r.raw_rule_id.startswith("acl")]
        rule_0 = [r for r in acl_rules if "rule0" in r.raw_rule_id][0]
        assert any(s.protocol == "esp" for s in rule_0.services)

    def test_esp_source_parsed(self):
        """esp 规则的源地址应为 10.0.0.0/24。"""
        result = self._parse()
        acl_rules = [r for r in result.rules if r.raw_rule_id.startswith("acl")]
        rule_0 = [r for r in acl_rules if "rule0" in r.raw_rule_id][0]
        src_nets = {str(a.network) for a in rule_0.src_ip if a.network}
        assert "10.0.0.0/24" in src_nets

    def test_ah_protocol_and_addresses(self):
        """ah 协议的源和目的地址应正确解析。"""
        result = self._parse()
        acl_rules = [r for r in result.rules if r.raw_rule_id.startswith("acl")]
        rule_1 = [r for r in acl_rules if "rule1" in r.raw_rule_id][0]
        assert any(s.protocol == "ah" for s in rule_1.services)
        src_nets = {str(a.network) for a in rule_1.src_ip if a.network}
        dst_nets = {str(a.network) for a in rule_1.dst_ip if a.network}
        assert "10.1.0.0/16" in src_nets
        assert "10.2.0.0/16" in dst_nets

    def test_known_proto_regression(self):
        """已知协议 tcp 仍应正常解析。"""
        from fw_analyzer.models.port_range import PortRange
        result = self._parse()
        acl_rules = [r for r in result.rules if r.raw_rule_id.startswith("acl")]
        rule_2 = [r for r in acl_rules if "rule2" in r.raw_rule_id][0]
        assert any(s.protocol == "tcp" for s in rule_2.services)
        assert any(
            s.dst_port.contains(PortRange.single(22)) for s in rule_2.services
        )

    def test_ipinip_still_works(self):
        """ipinip 作为已在白名单中的协议仍应正常解析。"""
        result = self._parse()
        acl_rules = [r for r in result.rules if r.raw_rule_id.startswith("acl")]
        rule_3 = [r for r in acl_rules if "rule3" in r.raw_rule_id][0]
        assert any(s.protocol == "ipinip" for s in rule_3.services)


# ------------------------------------------------------------------
# Cisco ASA ITO 工单号提取
# ------------------------------------------------------------------

class TestCiscoAsaTicketExtraction:
    """Cisco ASA 应从 object-group 名称中提取 ITO 工单号到 comment 字段。"""

    CISCO_ITO = """\
object-group network ITO-40213-SRC
 network-object host 10.1.1.1

object-group network ITO-40213-DST
 network-object host 10.2.2.2

object-group service ITO-40213-ports tcp
 port-object eq 443

access-list outside extended permit tcp object-group ITO-40213-SRC object-group ITO-40213-DST object-group ITO-40213-ports log
access-list outside extended permit ip host 10.3.3.3 host 10.4.4.4
access-list outside extended permit tcp object-group ITO-37961-source object-group ITO-40213-DST eq 80
"""

    def _parse(self):
        return get_parser("cisco-asa").parse(self.CISCO_ITO)

    def test_ito_extracted_single(self):
        """含单个 ITO 编号的行应提取到 comment。"""
        result = self._parse()
        rule_0 = result.rules[0]
        assert "ITO-40213" in rule_0.comment

    def test_ito_deduped(self):
        """同一行多次出现的 ITO 编号应去重。"""
        result = self._parse()
        rule_0 = result.rules[0]
        # ITO-40213 出现 3 次（SRC, DST, ports），comment 应只有一个
        assert rule_0.comment.count("ITO-40213") == 1

    def test_no_ito_empty_comment(self):
        """无 ITO 引用的 ACL 行 comment 应为空。"""
        result = self._parse()
        rule_1 = result.rules[1]
        assert rule_1.comment == ""

    def test_multiple_ito_numbers(self):
        """含多个不同 ITO 编号的行应全部提取。"""
        result = self._parse()
        rule_2 = result.rules[2]
        assert "ITO-37961" in rule_2.comment
        assert "ITO-40213" in rule_2.comment

    def test_ticket_populated_after_compliance(self):
        """经合规分析后 ticket 字段应自动填充。"""
        from fw_analyzer.analyzers.compliance import ComplianceAnalyzer
        from fw_analyzer.config import AnalyzerConfig
        result = self._parse()
        config = AnalyzerConfig()
        ComplianceAnalyzer().analyze(result.rules, config)
        rule_0 = result.rules[0]
        assert rule_0.ticket == "ITO-40213"
