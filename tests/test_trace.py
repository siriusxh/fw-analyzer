"""
tests/test_trace.py

测试 Trace 引擎：单条查询、批量查询、匹配语义、CSV 加载。
"""
from __future__ import annotations

from ipaddress import IPv4Network

import pytest

from fw_analyzer.trace import TraceEngine, TraceQuery, TraceResult, load_trace_queries_from_csv
from fw_analyzer.models.rule import FlatRule
from fw_analyzer.models.object_store import AddressObject, ServiceObject
from fw_analyzer.models.port_range import PortRange


# ------------------------------------------------------------------
# 测试辅助
# ------------------------------------------------------------------

def _addr(cidr: str) -> AddressObject:
    net = IPv4Network(cidr, strict=False)
    t = "host" if net.prefixlen == 32 else ("any" if str(net) == "0.0.0.0/0" else "subnet")
    return AddressObject(name=cidr, type=t, value=str(net), network=net)


def _any_addr() -> AddressObject:
    return AddressObject(name="any", type="any", value="0.0.0.0/0",
                         network=IPv4Network("0.0.0.0/0"))


def _svc(proto: str, dst_start: int = 0, dst_end: int = 65535) -> ServiceObject:
    return ServiceObject(
        name=f"{proto}/{dst_start}-{dst_end}",
        protocol=proto,
        src_port=PortRange.any(),
        dst_port=PortRange(dst_start, dst_end),
    )


def _any_svc() -> ServiceObject:
    return ServiceObject(name="any", protocol="any",
                         src_port=PortRange.any(), dst_port=PortRange.any())


def _rule(
    seq: int,
    action: str = "permit",
    src_addrs=None,
    dst_addrs=None,
    services=None,
    enabled: bool = True,
) -> FlatRule:
    return FlatRule(
        vendor="test",
        raw_rule_id=f"rule-{seq}",
        rule_name=f"rule-{seq}",
        seq=seq,
        src_ip=src_addrs or [_any_addr()],
        dst_ip=dst_addrs or [_any_addr()],
        services=services or [_any_svc()],
        action=action,  # type: ignore[arg-type]
        enabled=enabled,
    )


# ------------------------------------------------------------------
# TraceQuery 单元测试
# ------------------------------------------------------------------

class TestTraceQuery:
    def test_single_ip_normalized(self):
        q = TraceQuery(src_ip="10.0.0.1", dst_ip="8.8.8.8")
        assert q.src_ip == "10.0.0.1/32"
        assert q.dst_ip == "8.8.8.8/32"

    def test_cidr_preserved(self):
        q = TraceQuery(src_ip="192.168.0.0/24", dst_ip="10.0.0.0/8")
        assert q.src_ip == "192.168.0.0/24"
        assert q.dst_ip == "10.0.0.0/8"

    def test_protocol_lowercase(self):
        q = TraceQuery(src_ip="10.0.0.1", dst_ip="8.8.8.8", protocol="TCP")
        assert q.protocol == "tcp"

    def test_src_network_property(self):
        q = TraceQuery(src_ip="192.168.1.0/24", dst_ip="0.0.0.0/0")
        assert q.src_network == IPv4Network("192.168.1.0/24")

    def test_to_dict(self):
        q = TraceQuery(src_ip="10.0.0.1", dst_ip="8.8.8.8", protocol="tcp", dst_port=443)
        d = q.to_dict()
        assert d["src_ip"] == "10.0.0.1/32"
        assert d["dst_port"] == 443


# ------------------------------------------------------------------
# TraceEngine 基本匹配
# ------------------------------------------------------------------

class TestTraceEngineBasic:
    def test_match_any_any(self):
        """permit any any 应匹配所有查询。"""
        rules = [_rule(0, action="permit")]
        engine = TraceEngine(rules)
        result = engine.trace(TraceQuery(src_ip="1.2.3.4", dst_ip="5.6.7.8"))
        assert result.matched
        assert result.action == "permit"

    def test_no_match_returns_no_match(self):
        """空规则列表应返回 no-match。"""
        engine = TraceEngine([])
        result = engine.trace(TraceQuery(src_ip="1.2.3.4", dst_ip="5.6.7.8"))
        assert not result.matched
        assert result.action == "no-match"

    def test_first_match_wins(self):
        """first-match 语义：第一条 deny 命中，不继续往后找 permit。"""
        rules = [
            _rule(0, action="deny"),
            _rule(1, action="permit"),
        ]
        engine = TraceEngine(rules)
        result = engine.trace(TraceQuery(src_ip="1.2.3.4", dst_ip="5.6.7.8"))
        assert result.matched
        assert result.action == "deny"
        assert result.matched_rule.seq == 0

    def test_disabled_rule_skipped(self):
        """禁用规则跳过，不参与匹配。"""
        rules = [
            _rule(0, action="permit", enabled=False),
            _rule(1, action="deny"),
        ]
        engine = TraceEngine(rules)
        result = engine.trace(TraceQuery(src_ip="1.2.3.4", dst_ip="5.6.7.8"))
        assert result.matched
        assert result.matched_rule.seq == 1  # 跳过了 seq=0


# ------------------------------------------------------------------
# TraceEngine 地址匹配语义
# ------------------------------------------------------------------

class TestTraceEngineAddressMatching:
    def test_single_ip_contained_in_subnet(self):
        """/32 查询被规则中的子网包含 → 命中。"""
        rules = [_rule(0, src_addrs=[_addr("192.168.1.0/24")])]
        engine = TraceEngine(rules)
        result = engine.trace(TraceQuery(src_ip="192.168.1.100", dst_ip="any"))
        assert result.matched

    def test_single_ip_not_in_subnet(self):
        """/32 查询不在规则子网中 → 不命中。"""
        rules = [_rule(0, src_addrs=[_addr("192.168.1.0/24")])]
        engine = TraceEngine(rules)
        result = engine.trace(TraceQuery(src_ip="10.0.0.1", dst_ip="any"))
        assert not result.matched

    def test_subnet_query_fully_covered(self):
        """网段查询被规则完全覆盖 → 命中（全覆盖语义）。"""
        rules = [_rule(0, dst_addrs=[_addr("10.0.0.0/8")])]
        engine = TraceEngine(rules)
        result = engine.trace(TraceQuery(src_ip="any", dst_ip="10.1.0.0/16"))
        assert result.matched

    def test_subnet_query_not_fully_covered(self):
        """网段查询未被任何单一规则对象完全覆盖 → 不命中。"""
        rules = [_rule(0, dst_addrs=[_addr("10.1.0.0/24")])]
        engine = TraceEngine(rules)
        # 查询 10.0.0.0/8 包含了 10.1.0.0/24，但规则不覆盖整个 /8
        result = engine.trace(TraceQuery(src_ip="any", dst_ip="10.0.0.0/8"))
        assert not result.matched

    def test_any_destination_matches_all(self):
        """规则目的为 any，查询任何 IP 都命中。"""
        rules = [_rule(0, dst_addrs=[_any_addr()])]
        engine = TraceEngine(rules)
        result = engine.trace(TraceQuery(src_ip="1.1.1.1", dst_ip="8.8.8.8"))
        assert result.matched

    def test_fqdn_addr_skipped(self):
        """FQDN 地址对象被跳过，match_note 中有说明。"""
        fqdn_obj = AddressObject(name="example.com", type="fqdn",
                                 value="example.com", network=None)
        rules = [_rule(0, dst_addrs=[fqdn_obj])]
        engine = TraceEngine(rules)
        result = engine.trace(TraceQuery(src_ip="1.1.1.1", dst_ip="8.8.8.8"))
        # 仅有 FQDN 对象无法命中
        assert not result.matched
        # match_note 应提及 FQDN
        assert "FQDN" in result.match_note or "fqdn" in result.match_note.lower()


# ------------------------------------------------------------------
# TraceEngine 服务匹配
# ------------------------------------------------------------------

class TestTraceEngineServiceMatching:
    def test_port_match(self):
        """查询端口 443 命中规则端口 443。"""
        rules = [_rule(0, services=[_svc("tcp", 443, 443)])]
        engine = TraceEngine(rules)
        result = engine.trace(TraceQuery(src_ip="1.1.1.1", dst_ip="2.2.2.2",
                                         protocol="tcp", dst_port=443))
        assert result.matched

    def test_port_mismatch(self):
        """查询端口 80 不命中规则端口 443。"""
        rules = [_rule(0, services=[_svc("tcp", 443, 443)])]
        engine = TraceEngine(rules)
        result = engine.trace(TraceQuery(src_ip="1.1.1.1", dst_ip="2.2.2.2",
                                         protocol="tcp", dst_port=80))
        assert not result.matched

    def test_protocol_mismatch(self):
        """查询协议 udp 不命中规则 tcp。"""
        rules = [_rule(0, services=[_svc("tcp", 80, 80)])]
        engine = TraceEngine(rules)
        result = engine.trace(TraceQuery(src_ip="1.1.1.1", dst_ip="2.2.2.2",
                                         protocol="udp", dst_port=80))
        assert not result.matched

    def test_any_service_matches_all(self):
        """规则服务为 any，查询任何协议/端口都命中。"""
        rules = [_rule(0, services=[_any_svc()])]
        engine = TraceEngine(rules)
        result = engine.trace(TraceQuery(src_ip="1.1.1.1", dst_ip="2.2.2.2",
                                         protocol="tcp", dst_port=3389))
        assert result.matched

    def test_port_range_match(self):
        """查询端口在范围内命中。"""
        rules = [_rule(0, services=[_svc("tcp", 8000, 9000)])]
        engine = TraceEngine(rules)
        result = engine.trace(TraceQuery(src_ip="1.1.1.1", dst_ip="2.2.2.2",
                                         protocol="tcp", dst_port=8080))
        assert result.matched


# ------------------------------------------------------------------
# all_matches 模式
# ------------------------------------------------------------------

class TestTraceEngineAllMatches:
    def test_all_matches_returns_all(self):
        """--all-matches 模式返回所有命中规则。"""
        rules = [
            _rule(0, action="permit"),
            _rule(1, action="deny"),
            _rule(2, action="permit"),
        ]
        engine = TraceEngine(rules)
        result = engine.trace(
            TraceQuery(src_ip="1.1.1.1", dst_ip="2.2.2.2"),
            first_match_only=False,
        )
        assert len(result.all_matches) == 3
        assert result.matched_rule.seq == 0  # 第一条作为主命中

    def test_first_match_only_returns_one(self):
        """first_match_only 模式只返回第一条。"""
        rules = [_rule(0), _rule(1), _rule(2)]
        engine = TraceEngine(rules)
        result = engine.trace(TraceQuery(src_ip="1.1.1.1", dst_ip="2.2.2.2"),
                               first_match_only=True)
        assert len(result.all_matches) == 1


# ------------------------------------------------------------------
# TraceResult.to_dict / to_csv_row
# ------------------------------------------------------------------

class TestTraceResult:
    def _make_result(self, matched=True) -> TraceResult:
        q = TraceQuery(src_ip="10.0.0.1", dst_ip="8.8.8.8", protocol="tcp", dst_port=443)
        if matched:
            rule = _rule(0, action="permit")
            return TraceResult(query=q, matched=True, matched_rule=rule,
                               action="permit", match_note="")
        return TraceResult(query=q, matched=False, action="no-match",
                           match_note="无规则命中")

    def test_to_dict_matched(self):
        tr = self._make_result(matched=True)
        d = tr.to_dict()
        assert d["matched"] is True
        assert d["action"] == "permit"
        assert d["matched_rule_id"] == "rule-0"

    def test_to_dict_unmatched(self):
        tr = self._make_result(matched=False)
        d = tr.to_dict()
        assert d["matched"] is False
        assert d["matched_rule_id"] == ""
        assert d["matched_seq"] == -1

    def test_to_csv_row(self):
        tr = self._make_result()
        row = tr.to_csv_row()
        assert "src_ip" in row
        assert "action" in row


# ------------------------------------------------------------------
# 批量 CSV 加载
# ------------------------------------------------------------------

class TestLoadTraceQueriesFromCsv:
    def test_basic_csv(self):
        csv = "10.0.0.1,8.8.8.8,udp,53\n"
        queries = load_trace_queries_from_csv(csv)
        assert len(queries) == 1
        assert queries[0].protocol == "udp"
        assert queries[0].dst_port == 53

    def test_with_label(self):
        csv = "10.0.0.1,8.8.8.8,tcp,443,,my-query\n"
        queries = load_trace_queries_from_csv(csv)
        assert queries[0].label == "my-query"

    def test_skip_comment_line(self):
        csv = "# this is a comment\n10.0.0.1,8.8.8.8,tcp,80\n"
        queries = load_trace_queries_from_csv(csv)
        assert len(queries) == 1

    def test_skip_empty_line(self):
        csv = "\n10.0.0.1,8.8.8.8,tcp,80\n\n"
        queries = load_trace_queries_from_csv(csv)
        assert len(queries) == 1

    def test_multiple_rows(self):
        csv = (
            "10.0.0.1,8.8.8.8,tcp,443\n"
            "192.168.1.0/24,0.0.0.0/0,udp,53\n"
            "172.16.0.1,10.0.0.1,icmp,0\n"
        )
        queries = load_trace_queries_from_csv(csv)
        assert len(queries) == 3
        assert queries[1].src_ip == "192.168.1.0/24"
