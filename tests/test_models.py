"""
tests/test_models.py

ip_utils / port_range / object_store 模型层单元测试。
"""
from __future__ import annotations

import pytest
from ipaddress import IPv4Network

from fw_analyzer.models.ip_utils import (
    is_wildcard_mask,
    is_contiguous_wildcard,
    wildcard_to_network,
    parse_ipv4_network,
    network_contains,
    NonContiguousWildcardError,
)
from fw_analyzer.models.port_range import PortRange
from fw_analyzer.models.object_store import ObjectStore


# ======================================================================
# TestIpUtils
# ======================================================================


class TestIpUtils:
    """ip_utils 工具函数测试。"""

    # --- is_wildcard_mask ---

    def test_is_wildcard_mask_zero(self):
        """0.0.0.0 视为 wildcard（ACL any）。"""
        assert is_wildcard_mask("0.0.0.0") is True

    def test_is_wildcard_mask_typical(self):
        """0.0.0.255 是典型的 wildcard。"""
        assert is_wildcard_mask("0.0.0.255") is True

    def test_is_wildcard_mask_subnet_255(self):
        """255.255.255.0 是 subnet mask，不是 wildcard。"""
        assert is_wildcard_mask("255.255.255.0") is False

    def test_is_wildcard_mask_all_ones(self):
        """255.255.255.255 不是 wildcard。"""
        assert is_wildcard_mask("255.255.255.255") is False

    def test_is_wildcard_mask_invalid(self):
        """非法字符串返回 False。"""
        assert is_wildcard_mask("not-a-mask") is False

    # --- is_contiguous_wildcard ---

    def test_contiguous_wildcard_standard(self):
        """0.0.0.255 是连续 wildcard。"""
        assert is_contiguous_wildcard("0.0.0.255") is True

    def test_contiguous_wildcard_zero(self):
        """0.0.0.0 是连续 wildcard（匹配单个 IP）。"""
        assert is_contiguous_wildcard("0.0.0.0") is True

    def test_non_contiguous_wildcard(self):
        """0.0.255.0 不是连续 wildcard。"""
        assert is_contiguous_wildcard("0.0.255.0") is False

    def test_contiguous_wildcard_invalid(self):
        """非法字符串返回 False。"""
        assert is_contiguous_wildcard("invalid") is False

    # --- wildcard_to_network ---

    def test_wildcard_to_network_24(self):
        """0.0.0.255 → /24"""
        net = wildcard_to_network("192.168.1.0", "0.0.0.255")
        assert net == IPv4Network("192.168.1.0/24")

    def test_wildcard_to_network_32(self):
        """0.0.0.0 → /32"""
        net = wildcard_to_network("10.0.0.1", "0.0.0.0")
        assert net == IPv4Network("10.0.0.1/32")

    def test_wildcard_to_network_non_contiguous_raises(self):
        """非连续 wildcard 抛出 NonContiguousWildcardError。"""
        with pytest.raises(NonContiguousWildcardError) as exc_info:
            wildcard_to_network("10.0.0.0", "0.0.255.0")
        assert "10.0.0.0" in str(exc_info.value)
        assert "0.0.255.0" in str(exc_info.value)

    # --- parse_ipv4_network（6 种格式）---

    def test_parse_cidr(self):
        assert parse_ipv4_network("192.168.1.0/24") == IPv4Network("192.168.1.0/24")

    def test_parse_single_ip(self):
        assert parse_ipv4_network("10.0.0.1") == IPv4Network("10.0.0.1/32")

    def test_parse_any(self):
        assert parse_ipv4_network("any") == IPv4Network("0.0.0.0/0")

    def test_parse_subnet_mask(self):
        assert parse_ipv4_network("172.16.0.0", "255.255.255.0") == IPv4Network("172.16.0.0/24")

    def test_parse_wildcard_mask(self):
        assert parse_ipv4_network("192.168.1.0", "0.0.0.255") == IPv4Network("192.168.1.0/24")

    def test_parse_host_keyword(self):
        assert parse_ipv4_network("host", "10.0.0.1") == IPv4Network("10.0.0.1/32")

    def test_parse_host_keyword_no_ip_raises(self):
        with pytest.raises(ValueError):
            parse_ipv4_network("host")

    def test_parse_invalid_raises(self):
        with pytest.raises(ValueError):
            parse_ipv4_network("not-an-ip")

    # --- network_contains ---

    def test_network_contains_same(self):
        net = IPv4Network("10.0.0.0/24")
        assert network_contains(net, net) is True

    def test_network_contains_subnet(self):
        outer = IPv4Network("10.0.0.0/16")
        inner = IPv4Network("10.0.1.0/24")
        assert network_contains(outer, inner) is True

    def test_network_not_contains(self):
        a = IPv4Network("10.0.0.0/24")
        b = IPv4Network("10.0.1.0/24")
        assert network_contains(a, b) is False

    def test_network_contains_any_covers_all(self):
        any_net = IPv4Network("0.0.0.0/0")
        specific = IPv4Network("10.0.0.1/32")
        assert network_contains(any_net, specific) is True


# ======================================================================
# TestPortRange
# ======================================================================


class TestPortRange:
    """port_range 模型测试。"""

    def test_any(self):
        pr = PortRange.any()
        assert pr.low == 0
        assert pr.high == 65535
        assert pr.is_any() is True

    def test_single(self):
        pr = PortRange.single(443)
        assert pr.low == 443
        assert pr.high == 443
        assert pr.is_single() is True

    def test_invalid_range_raises(self):
        with pytest.raises(ValueError):
            PortRange(1000, 999)  # low > high

    def test_out_of_range_raises(self):
        with pytest.raises(ValueError):
            PortRange(-1, 100)

    # --- from_string ---

    def test_from_string_any(self):
        assert PortRange.from_string("any") == PortRange(0, 65535)

    def test_from_string_single(self):
        assert PortRange.from_string("443") == PortRange(443, 443)

    def test_from_string_dash_range(self):
        assert PortRange.from_string("8080-8443") == PortRange(8080, 8443)

    def test_from_string_to_range(self):
        assert PortRange.from_string("80 to 443") == PortRange(80, 443)

    def test_from_string_range_keyword(self):
        assert PortRange.from_string("range 80 443") == PortRange(80, 443)

    def test_from_string_invalid_raises(self):
        with pytest.raises(ValueError):
            PortRange.from_string("not-a-port")

    # --- contains ---

    def test_contains_self(self):
        pr = PortRange(80, 443)
        assert pr.contains(pr) is True

    def test_contains_inner(self):
        outer = PortRange(80, 443)
        inner = PortRange(100, 200)
        assert outer.contains(inner) is True

    def test_not_contains(self):
        a = PortRange(80, 443)
        b = PortRange(1, 65535)
        assert a.contains(b) is False

    def test_any_contains_all(self):
        assert PortRange.any().contains(PortRange.single(443)) is True

    # --- overlaps ---

    def test_overlaps_true(self):
        a = PortRange(80, 443)
        b = PortRange(400, 500)
        assert a.overlaps(b) is True

    def test_overlaps_false(self):
        a = PortRange(80, 200)
        b = PortRange(300, 500)
        assert a.overlaps(b) is False

    def test_overlaps_adjacent(self):
        """相邻区间不重叠。"""
        a = PortRange(80, 199)
        b = PortRange(200, 300)
        assert a.overlaps(b) is False

    # --- str/repr ---

    def test_str_any(self):
        assert str(PortRange.any()) == "any"

    def test_str_single(self):
        assert str(PortRange.single(22)) == "22"

    def test_str_range(self):
        assert str(PortRange(80, 443)) == "80-443"


# ======================================================================
# TestObjectStore
# ======================================================================


class TestObjectStore:
    """object_store 对象存储与展开测试。"""

    def test_add_and_resolve_host(self):
        """基本注册 → 展开。"""
        store = ObjectStore()
        store.add_address_object("h1", "host", "10.0.0.1")
        result = store.resolve_address("h1")
        assert len(result) == 1
        assert result[0].type == "host"
        assert result[0].network == IPv4Network("10.0.0.1/32")

    def test_nested_group_expand(self):
        """嵌套组展开。"""
        store = ObjectStore()
        store.add_address_object("h1", "host", "10.0.0.1")
        store.add_address_object("h2", "host", "10.0.0.2")
        store.add_address_group("grp1", ["h1", "h2"])
        store.add_address_group("grp2", ["grp1"])
        result = store.resolve_address("grp2")
        assert len(result) == 2
        values = {r.value for r in result}
        assert "10.0.0.1/32" in values
        assert "10.0.0.2/32" in values

    def test_deep_nesting_warning(self):
        """4 层嵌套触发 DEEP_NESTING 警告。"""
        store = ObjectStore()
        store.add_address_object("leaf", "host", "10.0.0.1")
        store.add_address_group("g1", ["leaf"])
        store.add_address_group("g2", ["g1"])
        store.add_address_group("g3", ["g2"])
        store.add_address_group("g4", ["g3"])  # g4 → g3 → g2 → g1 → leaf = depth 4
        result = store.resolve_address("g4")
        assert len(result) == 1
        deep_warnings = [w for w in store.warnings if w.code == "DEEP_NESTING"]
        assert len(deep_warnings) > 0

    def test_circular_reference(self):
        """循环引用检测。"""
        store = ObjectStore()
        store.add_address_group("a", ["b"])
        store.add_address_group("b", ["a"])
        result = store.resolve_address("a")
        circ_warnings = [w for w in store.warnings if w.code == "CIRCULAR_REFERENCE"]
        assert len(circ_warnings) > 0

    def test_fqdn_object(self):
        """FQDN 对象保留原文，network=None。"""
        store = ObjectStore()
        store.add_address_object("fqdn1", "fqdn", "www.example.com")
        result = store.resolve_address("fqdn1")
        assert len(result) == 1
        assert result[0].type == "fqdn"
        assert result[0].network is None
        assert result[0].value == "www.example.com"

    def test_non_contiguous_wildcard_warning(self):
        """非连续 wildcard 产生 NON_CONTIGUOUS_WILDCARD 警告。"""
        store = ObjectStore()
        store.add_address_object("nc", "subnet", "10.0.0.0", mask="0.0.255.0")
        nc_warnings = [w for w in store.warnings if w.code == "NON_CONTIGUOUS_WILDCARD"]
        assert len(nc_warnings) > 0
        # 对象类型降级为 unknown
        result = store.resolve_address("nc")
        assert result[0].type == "unknown"

    def test_unresolved_object(self):
        """不存在对象引用产生 UNRESOLVED_OBJECT 警告。"""
        store = ObjectStore()
        result = store.resolve_address("nonexistent")
        assert len(result) == 1
        assert result[0].type == "unknown"
        unresolved = [w for w in store.warnings if w.code == "UNRESOLVED_OBJECT"]
        assert len(unresolved) > 0

    def test_has_address(self):
        store = ObjectStore()
        store.add_address_object("h1", "host", "10.0.0.1")
        store.add_address_group("g1", ["h1"])
        assert store.has_address("h1") is True
        assert store.has_address("g1") is True
        assert store.has_address("nope") is False

    def test_has_service(self):
        store = ObjectStore()
        store.add_service_object("svc1", "tcp", dst_port=PortRange.single(443))
        store.add_service_group("sg1", ["svc1"])
        assert store.has_service("svc1") is True
        assert store.has_service("sg1") is True
        assert store.has_service("nope") is False

    def test_clear_warnings(self):
        store = ObjectStore()
        store.resolve_address("nonexistent")  # 产生警告
        assert len(store.warnings) > 0
        store.clear_warnings()
        assert len(store.warnings) == 0

    def test_resolve_any(self):
        """any 关键字直接返回 0.0.0.0/0。"""
        store = ObjectStore()
        result = store.resolve_address("any")
        assert len(result) == 1
        assert result[0].type == "any"
        assert result[0].network == IPv4Network("0.0.0.0/0")

    def test_resolve_service_any(self):
        """any 服务。"""
        store = ObjectStore()
        result = store.resolve_service("any")
        assert len(result) == 1
        assert result[0].protocol == "any"

    def test_resolve_service_protocol_name(self):
        """直接用协议名称作为服务。"""
        store = ObjectStore()
        result = store.resolve_service("tcp")
        assert len(result) == 1
        assert result[0].protocol == "tcp"
        assert result[0].dst_port.is_any()

    def test_service_group_expand(self):
        """服务组展开。"""
        store = ObjectStore()
        store.add_service_object("https", "tcp", dst_port=PortRange.single(443))
        store.add_service_object("ssh", "tcp", dst_port=PortRange.single(22))
        store.add_service_group("admin", ["https", "ssh"])
        result = store.resolve_service("admin")
        assert len(result) == 2
        ports = {r.dst_port.low for r in result}
        assert 443 in ports
        assert 22 in ports

    def test_service_circular_reference(self):
        """服务组循环引用。"""
        store = ObjectStore()
        store.add_service_group("a", ["b"])
        store.add_service_group("b", ["a"])
        result = store.resolve_service("a")
        circ = [w for w in store.warnings if w.code == "CIRCULAR_REFERENCE"]
        assert len(circ) > 0
