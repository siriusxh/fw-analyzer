"""
tests/test_exporters.py

测试三个导出器：CSV、JSON、Markdown。
验证输出格式正确、内容完整、无 IO 副作用（只返回字符串）。
"""
from __future__ import annotations

import csv
import io
import json
from ipaddress import IPv4Network

import pytest

from fw_analyzer.exporters.csv_exporter import CsvExporter
from fw_analyzer.exporters.json_exporter import JsonExporter
from fw_analyzer.exporters.markdown_exporter import MarkdownExporter
from fw_analyzer.analyzers.engine import AnalysisResult
from fw_analyzer.trace import TraceQuery, TraceResult
from fw_analyzer.models.rule import FlatRule
from fw_analyzer.models.object_store import AddressObject, ServiceObject
from fw_analyzer.models.port_range import PortRange
from fw_analyzer.parsers import get_parser


# ------------------------------------------------------------------
# 测试辅助
# ------------------------------------------------------------------

def _make_analysis_result(n_rules: int = 3) -> AnalysisResult:
    """构造用于测试的 AnalysisResult。"""
    rules = []
    for i in range(n_rules):
        net = IPv4Network(f"10.{i}.0.0/24")
        rule = FlatRule(
            vendor="test",
            raw_rule_id=f"rule-{i}",
            rule_name=f"test-rule-{i}",
            seq=i,
            src_ip=[AddressObject(
                name=str(net), type="subnet", value=str(net), network=net,
            )],
            dst_ip=[AddressObject(
                name="any", type="any", value="0.0.0.0/0",
                network=IPv4Network("0.0.0.0/0"),
            )],
            services=[ServiceObject(
                name="tcp/443",
                protocol="tcp",
                src_port=PortRange.any(),
                dst_port=PortRange(443, 443),
            )],
            action="permit",
            enabled=(i % 2 == 0),
            comment=f"rule {i} comment" if i > 0 else "",
        )
        if i == 1:
            rule.analysis_tags = ["SHADOW:by=rule-0"]
        rules.append(rule)

    return AnalysisResult(
        rules=rules,
        parse_warnings=[],
        analysis_warnings=[],
        vendor="test",
        source_file="test.cfg",
    )


def _make_trace_results() -> list[TraceResult]:
    q1 = TraceQuery(src_ip="10.0.0.1", dst_ip="8.8.8.8", protocol="tcp", dst_port=443)
    q2 = TraceQuery(src_ip="172.16.0.1", dst_ip="1.2.3.4", protocol="udp", dst_port=53)

    rule = FlatRule(
        vendor="test", raw_rule_id="r1", rule_name="permit-https",
        seq=0, action="permit", enabled=True,
    )

    return [
        TraceResult(query=q1, matched=True, matched_rule=rule,
                    action="permit", match_note=""),
        TraceResult(query=q2, matched=False, action="no-match",
                    match_note="无规则命中"),
    ]


# ------------------------------------------------------------------
# CSV 导出器
# ------------------------------------------------------------------

class TestCsvExporter:
    def test_returns_string(self):
        result = _make_analysis_result()
        out = CsvExporter().export(result)
        assert isinstance(out, str)

    def test_has_bom(self):
        out = CsvExporter().export(_make_analysis_result())
        assert out.startswith("\ufeff")

    def test_has_header(self):
        out = CsvExporter().export(_make_analysis_result())
        # 去掉 BOM
        clean = out.lstrip("\ufeff")
        reader = csv.DictReader(io.StringIO(clean))
        fieldnames = reader.fieldnames or []
        assert "rule_id" in fieldnames
        assert "action" in fieldnames
        assert "src_ip" in fieldnames
        assert "dst_ip" in fieldnames

    def test_row_count(self):
        n = 5
        result = _make_analysis_result(n_rules=n)
        out = CsvExporter().export(result)
        clean = out.lstrip("\ufeff")
        rows = list(csv.DictReader(io.StringIO(clean)))
        assert len(rows) == n

    def test_action_values(self):
        result = _make_analysis_result()
        out = CsvExporter().export(result)
        clean = out.lstrip("\ufeff")
        rows = list(csv.DictReader(io.StringIO(clean)))
        for row in rows:
            assert row["action"] in ("permit", "deny", "drop", "reject")

    def test_export_trace_returns_string(self):
        out = CsvExporter().export_trace(_make_trace_results())
        assert isinstance(out, str)

    def test_export_trace_row_count(self):
        results = _make_trace_results()
        out = CsvExporter().export_trace(results)
        clean = out.lstrip("\ufeff")
        rows = list(csv.DictReader(io.StringIO(clean)))
        assert len(rows) == len(results)

    def test_export_trace_matched_field(self):
        out = CsvExporter().export_trace(_make_trace_results())
        clean = out.lstrip("\ufeff")
        rows = list(csv.DictReader(io.StringIO(clean)))
        # 第一条命中，第二条未命中
        assert rows[0]["matched"] in ("True", "true", "1", True)
        assert rows[1]["matched"] in ("False", "false", "0", False)


# ------------------------------------------------------------------
# JSON 导出器
# ------------------------------------------------------------------

class TestJsonExporter:
    def test_returns_string(self):
        out = JsonExporter().export(_make_analysis_result())
        assert isinstance(out, str)

    def test_valid_json(self):
        out = JsonExporter().export(_make_analysis_result())
        data = json.loads(out)
        assert isinstance(data, dict)

    def test_top_level_keys(self):
        data = json.loads(JsonExporter().export(_make_analysis_result()))
        assert "vendor" in data
        assert "rules" in data
        assert "rule_count" in data

    def test_rules_array(self):
        n = 4
        data = json.loads(JsonExporter().export(_make_analysis_result(n_rules=n)))
        assert len(data["rules"]) == n

    def test_rule_has_expected_fields(self):
        data = json.loads(JsonExporter().export(_make_analysis_result()))
        rule = data["rules"][0]
        for key in ("vendor", "raw_rule_id", "rule_name", "seq", "action",
                    "src_ip", "dst_ip", "services", "enabled"):
            assert key in rule, f"缺少字段: {key}"

    def test_export_trace_returns_string(self):
        out = JsonExporter().export_trace(_make_trace_results())
        assert isinstance(out, str)

    def test_export_trace_valid_json(self):
        out = JsonExporter().export_trace(_make_trace_results())
        data = json.loads(out)
        assert isinstance(data, list)
        assert len(data) == 2

    def test_export_trace_matched_field(self):
        data = json.loads(JsonExporter().export_trace(_make_trace_results()))
        assert data[0]["matched"] is True
        assert data[1]["matched"] is False


# ------------------------------------------------------------------
# Markdown 导出器
# ------------------------------------------------------------------

class TestMarkdownExporter:
    def test_returns_string(self):
        out = MarkdownExporter().export(_make_analysis_result())
        assert isinstance(out, str)

    def test_has_title(self):
        out = MarkdownExporter().export(_make_analysis_result())
        assert "# 防火墙规则分析报告" in out

    def test_has_overview_section(self):
        out = MarkdownExporter().export(_make_analysis_result())
        assert "## 概览" in out

    def test_has_rules_section(self):
        out = MarkdownExporter().export(_make_analysis_result())
        assert "## 规则列表" in out

    def test_shadow_section_present_when_tagged(self):
        result = _make_analysis_result()
        # rule-1 已经有 SHADOW 标签
        out = MarkdownExporter().export(result)
        assert "## 影子规则" in out

    def test_shadow_section_absent_when_no_shadow(self):
        result = _make_analysis_result(n_rules=2)
        # 清除所有标签
        for r in result.rules:
            r.analysis_tags = []
        out = MarkdownExporter().export(result)
        assert "## 影子规则" not in out

    def test_source_file_in_report(self):
        result = _make_analysis_result()
        out = MarkdownExporter().export(result)
        assert "test.cfg" in out

    def test_export_trace_returns_string(self):
        out = MarkdownExporter().export_trace(_make_trace_results())
        assert isinstance(out, str)

    def test_export_trace_has_title(self):
        out = MarkdownExporter().export_trace(_make_trace_results())
        assert "# 访问需求 Trace 分析报告" in out

    def test_export_trace_has_detail_section(self):
        out = MarkdownExporter().export_trace(_make_trace_results())
        assert "## 详细结果" in out


# ------------------------------------------------------------------
# 标签分类统计表测试
# ------------------------------------------------------------------

class TestMarkdownTagBreakdown:
    """测试 Markdown 报告中的标签分类统计表。"""

    def _make_tagged_result(self, tags_per_rule: list[list[str]]) -> AnalysisResult:
        """快速构造带指定标签的 AnalysisResult。"""
        rules = []
        for i, tags in enumerate(tags_per_rule):
            net = IPv4Network(f"10.{i}.0.0/24")
            rule = FlatRule(
                vendor="test",
                raw_rule_id=f"rule-{i}",
                rule_name=f"test-rule-{i}",
                seq=i,
                src_ip=[AddressObject(name=str(net), type="subnet", value=str(net), network=net)],
                dst_ip=[AddressObject(name="any", type="any", value="0.0.0.0/0",
                                      network=IPv4Network("0.0.0.0/0"))],
                services=[ServiceObject(name="tcp/443", protocol="tcp",
                                        src_port=PortRange.any(), dst_port=PortRange(443, 443))],
                action="permit",
                enabled=True,
                analysis_tags=list(tags),  # copy
            )
            rules.append(rule)
        return AnalysisResult(
            rules=rules, parse_warnings=[], analysis_warnings=[],
            vendor="test", source_file="test.cfg",
        )

    def test_no_tags_no_section(self):
        """无标签时不输出标签分类统计。"""
        result = self._make_tagged_result([[], []])
        out = MarkdownExporter().export(result)
        assert "## 标签分类统计" not in out

    def test_section_present_with_tags(self):
        """有标签时输出标签分类统计。"""
        result = self._make_tagged_result([["SHADOW:by=rule-0"], []])
        out = MarkdownExporter().export(result)
        assert "## 标签分类统计" in out

    def test_shadow_count(self):
        """SHADOW 标签归一化并正确计数。"""
        result = self._make_tagged_result([
            ["SHADOW:by=rule-0"],
            ["SHADOW:by=rule-1"],
            [],
        ])
        out = MarkdownExporter().export(result)
        assert "| 质量问题 | `SHADOW` | 2 | 问题 |" in out

    def test_shadow_conflict_counted_separately(self):
        """SHADOW_CONFLICT 与 SHADOW 分开统计。"""
        result = self._make_tagged_result([
            ["SHADOW:by=rule-0"],
            ["SHADOW_CONFLICT:by=rule-0"],
        ])
        out = MarkdownExporter().export(result)
        assert "| 质量问题 | `SHADOW` | 1 | 问题 |" in out
        assert "| 质量问题 | `SHADOW_CONFLICT` | 1 | 问题 |" in out

    def test_redundant_counted(self):
        """REDUNDANT 标签正确归一化计数。"""
        result = self._make_tagged_result([["REDUNDANT:dup_of=rule-0"]])
        out = MarkdownExporter().export(result)
        assert "| 质量问题 | `REDUNDANT` | 1 | 问题 |" in out

    def test_overwide_categories(self):
        """OVERWIDE 各等级独立计数。"""
        result = self._make_tagged_result([
            ["OVERWIDE:CRITICAL"],
            ["OVERWIDE:HIGH"],
            ["OVERWIDE:HIGH"],
        ])
        out = MarkdownExporter().export(result)
        assert "| 过宽风险 | `OVERWIDE:CRITICAL` | 1 | 问题 |" in out
        assert "| 过宽风险 | `OVERWIDE:HIGH` | 2 | 问题 |" in out

    def test_compliance_cleartext_normalized(self):
        """CLEARTEXT 带端口参数的标签归一化统计。"""
        result = self._make_tagged_result([
            ["COMPLIANCE:CLEARTEXT:port=23", "COMPLIANCE:CLEARTEXT:port=21"],
        ])
        out = MarkdownExporter().export(result)
        # 同一规则有两个 CLEARTEXT 标签，但归一化后只计一次
        assert "| 合规问题 | `COMPLIANCE:CLEARTEXT` | 1 | 问题 |" in out

    def test_compliance_high_risk_port_normalized(self):
        """HIGH_RISK_PORT 带端口参数的标签归一化统计。"""
        result = self._make_tagged_result([
            ["COMPLIANCE:HIGH_RISK_PORT:port=22"],
            ["COMPLIANCE:HIGH_RISK_PORT:port=3389"],
        ])
        out = MarkdownExporter().export(result)
        assert "| 合规问题 | `COMPLIANCE:HIGH_RISK_PORT` | 2 | 问题 |" in out

    def test_no_ticket_counted(self):
        """NO_TICKET 标签正确计数，性质为问题。"""
        result = self._make_tagged_result([
            ["COMPLIANCE:NO_TICKET"],
            ["COMPLIANCE:NO_TICKET"],
            [],
        ])
        out = MarkdownExporter().export(result)
        assert "| 合规问题 | `COMPLIANCE:NO_TICKET` | 2 | 问题 |" in out

    def test_no_log_counted(self):
        """NO_LOG 标签正确计数，性质为问题。"""
        result = self._make_tagged_result([["COMPLIANCE:NO_LOG"]])
        out = MarkdownExporter().export(result)
        assert "| 合规问题 | `COMPLIANCE:NO_LOG` | 1 | 问题 |" in out

    def test_informational_tags_marked(self):
        """信息性标签标注为'信息'而非'问题'。"""
        result = self._make_tagged_result([
            ["COMPLIANCE:NO_COMMENT"],
            ["COMPLIANCE:DISABLED_RULES"],
        ])
        out = MarkdownExporter().export(result)
        assert "| 合规信息 | `COMPLIANCE:NO_COMMENT` | 1 | 信息 |" in out
        assert "| 合规信息 | `COMPLIANCE:DISABLED_RULES` | 1 | 信息 |" in out

    def test_section_between_overview_and_warnings(self):
        """标签分类统计表位于概览和解析警告之间。"""
        from fw_analyzer.models.rule import Warning, WarningSeverity
        result = self._make_tagged_result([["SHADOW:by=rule-0"]])
        result.parse_warnings = [Warning(
            code="PARSE_WARN", message="test warning",
            severity=WarningSeverity.WARN,
        )]
        out = MarkdownExporter().export(result)
        pos_overview = out.index("## 概览")
        pos_breakdown = out.index("## 标签分类统计")
        pos_warnings = out.index("## 解析警告")
        assert pos_overview < pos_breakdown < pos_warnings

    def test_mixed_tags_multiple_categories(self):
        """多种标签混合时各类别都正确显示。"""
        result = self._make_tagged_result([
            ["SHADOW:by=rule-0", "COMPLIANCE:NO_TICKET", "COMPLIANCE:NO_LOG"],
            ["OVERWIDE:HIGH", "COMPLIANCE:NO_COMMENT"],
            ["COMPLIANCE:DISABLED_RULES"],
        ])
        out = MarkdownExporter().export(result)
        assert "质量问题" in out
        assert "过宽风险" in out
        assert "合规问题" in out
        assert "合规信息" in out

    def test_zero_count_tags_omitted(self):
        """计数为 0 的标签不出现在表格中。"""
        result = self._make_tagged_result([["SHADOW:by=rule-0"]])
        out = MarkdownExporter().export(result)
        assert "REDUNDANT" not in out
        assert "OVERWIDE" not in out


# ------------------------------------------------------------------
# 使用真实解析结果的集成测试
# ------------------------------------------------------------------

class TestExportersWithRealParse:
    def test_csv_from_huawei(self, huawei_cfg):
        from fw_analyzer.analyzers.engine import AnalysisEngine
        parse_result = get_parser("huawei").parse(huawei_cfg)
        result = AnalysisEngine().analyze(parse_result)
        out = CsvExporter().export(result)
        assert isinstance(out, str)
        clean = out.lstrip("\ufeff")
        rows = list(csv.DictReader(io.StringIO(clean)))
        assert len(rows) == result.rule_count

    def test_json_from_cisco(self, cisco_cfg):
        from fw_analyzer.analyzers.engine import AnalysisEngine
        parse_result = get_parser("cisco-asa").parse(cisco_cfg)
        result = AnalysisEngine().analyze(parse_result)
        data = json.loads(JsonExporter().export(result))
        assert data["vendor"] == "cisco-asa"

    def test_markdown_from_paloalto(self, paloalto_cfg):
        from fw_analyzer.analyzers.engine import AnalysisEngine
        parse_result = get_parser("paloalto").parse(paloalto_cfg)
        result = AnalysisEngine().analyze(parse_result)
        out = MarkdownExporter().export(result)
        assert "paloalto" in out.lower() or "pan" in out.lower() or "# 防火墙" in out


# ------------------------------------------------------------------
# CSV 导出器：url_category 和 shadow 列
# ------------------------------------------------------------------

class TestCsvExporterNewColumns:
    """测试 CSV 导出器的 url_category 和 shadow 列。"""

    def test_csv_has_url_category_column(self):
        """CSV 表头包含 url_category。"""
        result = _make_analysis_result()
        out = CsvExporter().export(result)
        clean = out.lstrip("\ufeff")
        reader = csv.DictReader(io.StringIO(clean))
        assert "url_category" in (reader.fieldnames or [])

    def test_csv_has_shadow_column(self):
        """CSV 表头包含 shadow。"""
        result = _make_analysis_result()
        out = CsvExporter().export(result)
        clean = out.lstrip("\ufeff")
        reader = csv.DictReader(io.StringIO(clean))
        assert "shadow" in (reader.fieldnames or [])

    def test_csv_shadow_column_has_shadow_tags(self):
        """shadow 列包含 SHADOW 标签。"""
        result = _make_analysis_result()
        # rule-1 has "SHADOW:by=rule-0"
        out = CsvExporter().export(result)
        clean = out.lstrip("\ufeff")
        rows = list(csv.DictReader(io.StringIO(clean)))
        assert "SHADOW:by=rule-0" in rows[1]["shadow"]

    def test_csv_analysis_tags_excludes_shadow(self):
        """analysis_tags 列不包含 SHADOW 标签。"""
        result = _make_analysis_result()
        out = CsvExporter().export(result)
        clean = out.lstrip("\ufeff")
        rows = list(csv.DictReader(io.StringIO(clean)))
        assert "SHADOW" not in rows[1].get("analysis_tags", "")

    def test_csv_url_category_value(self):
        """url_category 列包含正确值。"""
        result = _make_analysis_result()
        result.rules[0].url_category = "adult; malware"
        out = CsvExporter().export(result)
        clean = out.lstrip("\ufeff")
        rows = list(csv.DictReader(io.StringIO(clean)))
        assert rows[0]["url_category"] == "adult; malware"

    def test_csv_column_order(self):
        """url_category 和 shadow 在 ticket 和 analysis_tags 之间。"""
        from fw_analyzer.exporters.csv_exporter import RULE_CSV_FIELDS
        ticket_idx = RULE_CSV_FIELDS.index("ticket")
        url_cat_idx = RULE_CSV_FIELDS.index("url_category")
        shadow_idx = RULE_CSV_FIELDS.index("shadow")
        tags_idx = RULE_CSV_FIELDS.index("analysis_tags")
        assert ticket_idx < url_cat_idx < shadow_idx < tags_idx


# ------------------------------------------------------------------
# JSON 导出器：shadow 分离
# ------------------------------------------------------------------

class TestJsonExporterShadowSeparation:
    """测试 JSON 导出器的 shadow/analysis_tags 分离。"""

    def test_json_rule_has_shadow_field(self):
        """JSON 规则包含 shadow 字段（列表）。"""
        data = json.loads(JsonExporter().export(_make_analysis_result()))
        rule = data["rules"][1]  # rule-1 has SHADOW tag
        assert "shadow" in rule
        assert isinstance(rule["shadow"], list)
        assert "SHADOW:by=rule-0" in rule["shadow"]

    def test_json_analysis_tags_no_shadow(self):
        """JSON 规则的 analysis_tags 不含 SHADOW 标签。"""
        data = json.loads(JsonExporter().export(_make_analysis_result()))
        rule = data["rules"][1]
        assert all("SHADOW" not in t for t in rule["analysis_tags"])

    def test_json_rule_has_url_category(self):
        """JSON 规则包含 url_category 字段。"""
        result = _make_analysis_result()
        result.rules[0].url_category = "streaming"
        data = json.loads(JsonExporter().export(result))
        assert data["rules"][0]["url_category"] == "streaming"


# ------------------------------------------------------------------
# Markdown 导出器：URL分类 和 影子 列
# ------------------------------------------------------------------

class TestMarkdownExporterNewColumns:
    """测试 Markdown 导出器的 URL分类 和 影子 列。"""

    def test_markdown_table_has_url_category_header(self):
        """Markdown 规则表头包含 URL分类。"""
        out = MarkdownExporter().export(_make_analysis_result())
        assert "URL分类" in out

    def test_markdown_table_has_shadow_header(self):
        """Markdown 规则表头包含 影子。"""
        out = MarkdownExporter().export(_make_analysis_result())
        assert "影子" in out

    def test_markdown_url_category_skip_in_breakdown(self):
        """标签分类统计包含 URL_CATEGORY_SKIP。"""
        rules = []
        for i in range(2):
            net = IPv4Network(f"10.{i}.0.0/24")
            rule = FlatRule(
                vendor="test",
                raw_rule_id=f"rule-{i}",
                rule_name=f"test-rule-{i}",
                seq=i,
                src_ip=[AddressObject(name=str(net), type="subnet",
                                       value=str(net), network=net)],
                dst_ip=[AddressObject(name="any", type="any",
                                       value="0.0.0.0/0",
                                       network=IPv4Network("0.0.0.0/0"))],
                services=[ServiceObject(name="tcp/443", protocol="tcp",
                                         src_port=PortRange.any(),
                                         dst_port=PortRange(443, 443))],
                action="permit",
                enabled=True,
                analysis_tags=["URL_CATEGORY_SKIP"] if i == 0 else [],
            )
            rules.append(rule)
        result = AnalysisResult(
            rules=rules, parse_warnings=[], analysis_warnings=[],
            vendor="test", source_file="test.cfg",
        )
        out = MarkdownExporter().export(result)
        assert "分析跳过" in out
        assert "URL_CATEGORY_SKIP" in out
        assert "| 1 |" in out or "| 1 | 信息 |" in out


# ==================================================================
# Phase 4: ShadowDetailExporter + RawTextExtractor 测试
# ==================================================================


from fw_analyzer.exporters.shadow_detail_exporter import (
    ShadowDetailExporter,
    SHADOW_DETAIL_CSV_FIELDS,
    _build_shadow_pairs,
    _rule_desc,
)
from fw_analyzer.exporters.raw_text_extractor import RawTextExtractor


# ------------------------------------------------------------------
# RawTextExtractor 测试
# ------------------------------------------------------------------

class TestRawTextExtractorCisco:
    """RawTextExtractor — Cisco ASA 对象定义提取。"""

    CISCO_CONFIG = """\
object network web-server
 host 10.0.0.10

object network db-server
 host 10.0.0.20

object-group network internal-nets
 network-object 192.168.0.0 255.255.0.0
 network-object 10.0.0.0 255.255.0.0

object-group service admin-svcs tcp
 port-object eq 22
 port-object eq 443
"""

    def test_extract_object(self):
        ext = RawTextExtractor()
        result = ext.extract("cisco-asa", self.CISCO_CONFIG, ["web-server"])
        assert "web-server" in result
        assert "host 10.0.0.10" in result["web-server"]

    def test_extract_object_group(self):
        ext = RawTextExtractor()
        result = ext.extract("cisco-asa", self.CISCO_CONFIG, ["internal-nets"])
        assert "internal-nets" in result
        assert "192.168.0.0" in result["internal-nets"]

    def test_extract_service_group(self):
        ext = RawTextExtractor()
        result = ext.extract("cisco-asa", self.CISCO_CONFIG, ["admin-svcs"])
        assert "admin-svcs" in result
        assert "port-object eq 22" in result["admin-svcs"]

    def test_not_found_returns_empty(self):
        ext = RawTextExtractor()
        result = ext.extract("cisco-asa", self.CISCO_CONFIG, ["nonexistent"])
        assert result == {}

    def test_empty_names_returns_empty(self):
        ext = RawTextExtractor()
        result = ext.extract("cisco-asa", self.CISCO_CONFIG, [])
        assert result == {}


class TestRawTextExtractorHuawei:
    """RawTextExtractor — 华为 USG 对象定义提取。"""

    HUAWEI_CONFIG = """\
ip address-group inner-grp
  address 10.1.1.1 mask 255.255.255.255
  address 10.1.1.2 mask 255.255.255.255

ip service-set web-services type object
 service 0 protocol tcp destination-port 80 to 443
"""

    def test_extract_address_group(self):
        ext = RawTextExtractor()
        result = ext.extract("huawei", self.HUAWEI_CONFIG, ["inner-grp"])
        assert "inner-grp" in result
        assert "10.1.1.1" in result["inner-grp"]

    def test_extract_service_set(self):
        ext = RawTextExtractor()
        result = ext.extract("huawei", self.HUAWEI_CONFIG, ["web-services"])
        assert "web-services" in result
        assert "tcp" in result["web-services"]


class TestRawTextExtractorPaloAlto:
    """RawTextExtractor — PAN-OS set 格式对象定义提取。"""

    PA_CONFIG = """\
set address web-server ip-netmask 10.0.0.10/32
set address internal-net ip-netmask 192.168.1.0/24
set address-group internal-grp static [ internal-net ]
set service svc-https protocol tcp port 443
"""

    def test_extract_address(self):
        ext = RawTextExtractor()
        result = ext.extract("paloalto", self.PA_CONFIG, ["web-server"])
        assert "web-server" in result
        assert "10.0.0.10" in result["web-server"]

    def test_extract_address_group(self):
        ext = RawTextExtractor()
        result = ext.extract("paloalto", self.PA_CONFIG, ["internal-grp"])
        assert "internal-grp" in result

    def test_extract_service(self):
        ext = RawTextExtractor()
        result = ext.extract("paloalto", self.PA_CONFIG, ["svc-https"])
        assert "svc-https" in result
        assert "443" in result["svc-https"]


class TestRawTextExtractorFortinet:
    """RawTextExtractor — FortiGate 对象定义提取。"""

    FG_CONFIG = """\
config firewall address
    edit "internal-net"
        set subnet 192.168.1.0 255.255.255.0
    next
    edit "web-server"
        set type ipmask
        set subnet 10.0.0.10 255.255.255.255
    next
end
config firewall service custom
    edit "HTTPS"
        set protocol TCP
        set tcp-portrange 443
    next
end
"""

    def test_extract_address(self):
        ext = RawTextExtractor()
        result = ext.extract("fortinet", self.FG_CONFIG, ["internal-net"])
        assert "internal-net" in result
        assert "192.168.1.0" in result["internal-net"]

    def test_extract_service(self):
        ext = RawTextExtractor()
        result = ext.extract("fortinet", self.FG_CONFIG, ["HTTPS"])
        assert "HTTPS" in result
        assert "443" in result["HTTPS"]

    def test_not_found(self):
        ext = RawTextExtractor()
        result = ext.extract("fortinet", self.FG_CONFIG, ["nonexistent"])
        assert result == {}


class TestRawTextExtractorUnknownVendor:
    """RawTextExtractor — 未知厂商。"""

    def test_unknown_vendor_returns_empty(self):
        ext = RawTextExtractor()
        result = ext.extract("unknown-vendor", "some text", ["obj1"])
        assert result == {}

    def test_empty_config_returns_empty(self):
        ext = RawTextExtractor()
        result = ext.extract("cisco-asa", "", ["obj1"])
        assert result == {}


# ------------------------------------------------------------------
# ShadowDetailExporter 辅助函数测试
# ------------------------------------------------------------------

class TestBuildShadowPairs:
    """_build_shadow_pairs() 构建 shadow 关系对。"""

    def _make_result_with_shadows(self):
        """构造含 shadow 关系的 AnalysisResult。"""
        rules = []
        for i in range(3):
            net = IPv4Network(f"10.{i}.0.0/24")
            rule = FlatRule(
                vendor="test",
                raw_rule_id=f"rule-{i}",
                rule_name=f"test-rule-{i}",
                seq=i,
                src_ip=[AddressObject(name=str(net), type="subnet",
                                       value=str(net), network=net)],
                dst_ip=[AddressObject(name="any", type="any",
                                       value="0.0.0.0/0",
                                       network=IPv4Network("0.0.0.0/0"))],
                services=[ServiceObject(name="tcp/443", protocol="tcp",
                                         src_port=PortRange.any(),
                                         dst_port=PortRange(443, 443))],
                action="permit",
                enabled=True,
                raw_config=f"access-list test permit tcp 10.{i}.0.0/24 any eq 443",
            )
            rules.append(rule)

        # rule-1 shadowed by rule-0
        rules[1].analysis_tags = [
            "SHADOW:by=rule-0",
            "SHADOW_OTHERS:rule-2",  # this is a shadower tag, not victim
        ]
        # rule-2 shadow-conflicted by rule-0
        rules[2].analysis_tags = ["SHADOW_CONFLICT:by=rule-0"]
        # rule-0 is the shadower
        rules[0].analysis_tags = ["SHADOW_OTHERS:rule-1", "SHADOW_CONFLICT_OTHERS:rule-2"]

        return AnalysisResult(
            rules=rules, parse_warnings=[], analysis_warnings=[],
            vendor="test", source_file="test.cfg",
        )

    def test_pairs_count(self):
        result = self._make_result_with_shadows()
        pairs = _build_shadow_pairs(result)
        assert len(pairs) == 2

    def test_pairs_types(self):
        result = self._make_result_with_shadows()
        pairs = _build_shadow_pairs(result)
        types = {stype for _, stype, _ in pairs}
        assert "SHADOW" in types
        assert "SHADOW_CONFLICT" in types

    def test_pairs_sorted_by_seq(self):
        result = self._make_result_with_shadows()
        pairs = _build_shadow_pairs(result)
        # All pairs have shadower seq=0, should be sorted by victim seq
        victim_seqs = [v.seq for _, _, v in pairs]
        assert victim_seqs == sorted(victim_seqs)

    def test_no_shadow_returns_empty(self):
        result = _make_analysis_result()
        # clear all tags
        for r in result.rules:
            r.analysis_tags = []
        pairs = _build_shadow_pairs(result)
        assert pairs == []


class TestRuleDesc:
    """_rule_desc() 规则摘要描述。"""

    def test_basic_desc(self):
        rule = FlatRule(
            vendor="test", raw_rule_id="r1", rule_name="test",
            seq=0, action="permit", enabled=True,
        )
        desc = _rule_desc(rule)
        assert "PERMIT" in desc
        assert "any" in desc

    def test_desc_with_zone(self):
        rule = FlatRule(
            vendor="test", raw_rule_id="r1", rule_name="test",
            seq=0, action="deny", enabled=True,
            src_zone="trust", dst_zone="untrust",
        )
        desc = _rule_desc(rule)
        assert "DENY" in desc
        assert "trust" in desc
        assert "untrust" in desc

    def test_desc_with_ticket(self):
        rule = FlatRule(
            vendor="test", raw_rule_id="r1", rule_name="test",
            seq=0, action="permit", enabled=True,
            ticket="ITO-12345",
        )
        desc = _rule_desc(rule)
        assert "ITO-12345" in desc


# ------------------------------------------------------------------
# ShadowDetailExporter 完整输出测试
# ------------------------------------------------------------------

class TestShadowDetailExporterMarkdown:
    """ShadowDetailExporter.export_markdown() 测试。"""

    def _make_shadow_result(self):
        """构造含 shadow 关系的 AnalysisResult。"""
        rules = []
        for i in range(3):
            net = IPv4Network(f"10.{i}.0.0/24")
            rule = FlatRule(
                vendor="cisco-asa",
                raw_rule_id=f"rule-{i}",
                rule_name=f"test-rule-{i}",
                seq=i,
                src_ip=[AddressObject(name=str(net), type="subnet",
                                       value=str(net), network=net)],
                dst_ip=[AddressObject(name="any", type="any",
                                       value="0.0.0.0/0",
                                       network=IPv4Network("0.0.0.0/0"))],
                services=[ServiceObject(name="tcp/443", protocol="tcp",
                                         src_port=PortRange.any(),
                                         dst_port=PortRange(443, 443))],
                action="permit",
                enabled=True,
                raw_config=f"access-list test permit tcp 10.{i}.0.0/24 any eq 443",
                referenced_objects=["internal-nets"] if i == 0 else [],
            )
            rules.append(rule)

        # rule-1 shadowed by rule-0
        rules[1].analysis_tags = ["SHADOW:by=rule-0"]
        # rule-2 shadow-conflicted by rule-0, with extra tags
        rules[2].analysis_tags = [
            "SHADOW_CONFLICT:by=rule-0",
            "COMPLIANCE:NO_TICKET",
        ]

        return AnalysisResult(
            rules=rules, parse_warnings=[], analysis_warnings=[],
            vendor="cisco-asa", source_file="test.cfg",
        )

    def test_returns_string(self):
        result = self._make_shadow_result()
        exporter = ShadowDetailExporter()
        out = exporter.export_markdown(result)
        assert isinstance(out, str)

    def test_has_title(self):
        result = self._make_shadow_result()
        out = ShadowDetailExporter().export_markdown(result)
        assert "# Shadow Detail Report" in out

    def test_has_source_file(self):
        result = self._make_shadow_result()
        out = ShadowDetailExporter().export_markdown(result)
        assert "test.cfg" in out

    def test_has_shadower_heading(self):
        result = self._make_shadow_result()
        out = ShadowDetailExporter().export_markdown(result)
        assert "## rule-0" in out

    def test_has_victim_heading(self):
        result = self._make_shadow_result()
        out = ShadowDetailExporter().export_markdown(result)
        assert "#### → rule-1" in out
        assert "#### → rule-2" in out

    def test_has_shadow_type(self):
        result = self._make_shadow_result()
        out = ShadowDetailExporter().export_markdown(result)
        assert "[SHADOW]" in out
        assert "[SHADOW_CONFLICT]" in out

    def test_has_original_config(self):
        result = self._make_shadow_result()
        out = ShadowDetailExporter().export_markdown(result)
        assert "Original Config" in out
        assert "access-list test permit tcp" in out

    def test_has_summary_table(self):
        result = self._make_shadow_result()
        out = ShadowDetailExporter().export_markdown(result)
        assert "| Field | Value |" in out
        assert "| Action |" in out

    def test_has_other_tags(self):
        result = self._make_shadow_result()
        out = ShadowDetailExporter().export_markdown(result)
        assert "COMPLIANCE:NO_TICKET" in out

    def test_no_shadow_returns_no_relationships(self):
        result = _make_analysis_result()
        for r in result.rules:
            r.analysis_tags = []
        out = ShadowDetailExporter().export_markdown(result)
        assert "No shadow relationships found" in out

    def test_pair_count_in_header(self):
        result = self._make_shadow_result()
        out = ShadowDetailExporter().export_markdown(result)
        assert "Shadow pairs: **2**" in out


class TestShadowDetailExporterCsv:
    """ShadowDetailExporter.export_csv() 测试。"""

    def _make_shadow_result(self):
        rules = []
        for i in range(3):
            net = IPv4Network(f"10.{i}.0.0/24")
            rule = FlatRule(
                vendor="test",
                raw_rule_id=f"rule-{i}",
                rule_name=f"test-rule-{i}",
                seq=i,
                src_ip=[AddressObject(name=str(net), type="subnet",
                                       value=str(net), network=net)],
                dst_ip=[AddressObject(name="any", type="any",
                                       value="0.0.0.0/0",
                                       network=IPv4Network("0.0.0.0/0"))],
                services=[ServiceObject(name="tcp/443", protocol="tcp",
                                         src_port=PortRange.any(),
                                         dst_port=PortRange(443, 443))],
                action="permit",
                enabled=True,
                raw_config=f"access-list test permit tcp 10.{i}.0.0/24 any eq 443",
            )
            rules.append(rule)

        rules[1].analysis_tags = ["SHADOW:by=rule-0"]
        rules[2].analysis_tags = [
            "SHADOW_CONFLICT:by=rule-0",
            "OVERWIDE:HIGH",
        ]

        return AnalysisResult(
            rules=rules, parse_warnings=[], analysis_warnings=[],
            vendor="test", source_file="test.cfg",
        )

    def test_returns_string(self):
        result = self._make_shadow_result()
        out = ShadowDetailExporter().export_csv(result)
        assert isinstance(out, str)

    def test_has_bom(self):
        result = self._make_shadow_result()
        out = ShadowDetailExporter().export_csv(result)
        assert out.startswith("\ufeff")

    def test_has_12_columns(self):
        result = self._make_shadow_result()
        out = ShadowDetailExporter().export_csv(result)
        clean = out.lstrip("\ufeff")
        reader = csv.DictReader(io.StringIO(clean))
        assert reader.fieldnames is not None
        assert len(reader.fieldnames) == 12

    def test_csv_fields_match(self):
        result = self._make_shadow_result()
        out = ShadowDetailExporter().export_csv(result)
        clean = out.lstrip("\ufeff")
        reader = csv.DictReader(io.StringIO(clean))
        assert list(reader.fieldnames) == SHADOW_DETAIL_CSV_FIELDS

    def test_row_count(self):
        result = self._make_shadow_result()
        out = ShadowDetailExporter().export_csv(result)
        clean = out.lstrip("\ufeff")
        rows = list(csv.DictReader(io.StringIO(clean)))
        assert len(rows) == 2  # two shadow pairs

    def test_shadow_type_values(self):
        result = self._make_shadow_result()
        out = ShadowDetailExporter().export_csv(result)
        clean = out.lstrip("\ufeff")
        rows = list(csv.DictReader(io.StringIO(clean)))
        types = {row["shadow_type"] for row in rows}
        assert types == {"SHADOW", "SHADOW_CONFLICT"}

    def test_shadower_id_populated(self):
        result = self._make_shadow_result()
        out = ShadowDetailExporter().export_csv(result)
        clean = out.lstrip("\ufeff")
        rows = list(csv.DictReader(io.StringIO(clean)))
        assert all(row["shadower_id"] == "rule-0" for row in rows)

    def test_victim_ids_correct(self):
        result = self._make_shadow_result()
        out = ShadowDetailExporter().export_csv(result)
        clean = out.lstrip("\ufeff")
        rows = list(csv.DictReader(io.StringIO(clean)))
        victim_ids = {row["victim_id"] for row in rows}
        assert victim_ids == {"rule-1", "rule-2"}

    def test_victim_other_tags(self):
        result = self._make_shadow_result()
        out = ShadowDetailExporter().export_csv(result)
        clean = out.lstrip("\ufeff")
        rows = list(csv.DictReader(io.StringIO(clean)))
        conflict_row = [r for r in rows if r["victim_id"] == "rule-2"][0]
        assert "OVERWIDE:HIGH" in conflict_row["victim_other_tags"]

    def test_raw_config_in_csv(self):
        result = self._make_shadow_result()
        out = ShadowDetailExporter().export_csv(result)
        clean = out.lstrip("\ufeff")
        rows = list(csv.DictReader(io.StringIO(clean)))
        # All rules have raw_config set
        for row in rows:
            assert row["shadower_raw_config"] != ""
            assert row["victim_raw_config"] != ""

    def test_no_shadow_returns_header_only(self):
        result = _make_analysis_result()
        for r in result.rules:
            r.analysis_tags = []
        out = ShadowDetailExporter().export_csv(result)
        clean = out.lstrip("\ufeff")
        rows = list(csv.DictReader(io.StringIO(clean)))
        assert len(rows) == 0


# ------------------------------------------------------------------
# ShadowDetailExporter with config_text (object extraction)
# ------------------------------------------------------------------

class TestShadowDetailWithConfigText:
    """ShadowDetailExporter with config_text for object extraction."""

    CISCO_CONFIG = """\
object-group network internal-nets
 network-object 192.168.0.0 255.255.0.0
 network-object 10.0.0.0 255.255.0.0

access-list OUTSIDE_IN extended permit tcp object-group internal-nets any eq 443
access-list OUTSIDE_IN extended deny ip any any
"""

    def _make_result(self):
        rules = [
            FlatRule(
                vendor="cisco-asa",
                raw_rule_id="rule-0",
                rule_name="rule-0",
                seq=0,
                action="permit",
                enabled=True,
                raw_config="access-list OUTSIDE_IN extended permit tcp object-group internal-nets any eq 443",
                referenced_objects=["internal-nets"],
                analysis_tags=["SHADOW_OTHERS:rule-1"],
            ),
            FlatRule(
                vendor="cisco-asa",
                raw_rule_id="rule-1",
                rule_name="rule-1",
                seq=1,
                action="deny",
                enabled=True,
                raw_config="access-list OUTSIDE_IN extended deny ip any any",
                referenced_objects=[],
                analysis_tags=["SHADOW:by=rule-0"],
            ),
        ]
        return AnalysisResult(
            rules=rules, parse_warnings=[], analysis_warnings=[],
            vendor="cisco-asa", source_file="test.cfg",
        )

    def test_markdown_has_referenced_objects(self):
        result = self._make_result()
        exporter = ShadowDetailExporter(config_text=self.CISCO_CONFIG)
        out = exporter.export_markdown(result)
        assert "Referenced Objects" in out
        assert "192.168.0.0" in out

    def test_csv_has_object_definitions(self):
        result = self._make_result()
        exporter = ShadowDetailExporter(config_text=self.CISCO_CONFIG)
        out = exporter.export_csv(result)
        clean = out.lstrip("\ufeff")
        rows = list(csv.DictReader(io.StringIO(clean)))
        assert len(rows) == 1
        assert "192.168.0.0" in rows[0]["shadower_objects"]


# ------------------------------------------------------------------
# ShadowDetailExporter integration with real parse
# ------------------------------------------------------------------

class TestShadowDetailIntegration:
    """ShadowDetailExporter 使用真实解析+分析结果的集成测试。"""

    def test_cisco_shadow_detail_roundtrip(self, cisco_complex_cfg):
        """Cisco 复杂配置 → 解析 → 分析 → shadow detail 导出不报错。"""
        from fw_analyzer.analyzers.engine import AnalysisEngine
        parse_result = get_parser("cisco-asa").parse(cisco_complex_cfg)
        analysis = AnalysisEngine().analyze(parse_result)
        exporter = ShadowDetailExporter(config_text=cisco_complex_cfg)
        md = exporter.export_markdown(analysis)
        csv_out = exporter.export_csv(analysis)
        assert isinstance(md, str)
        assert isinstance(csv_out, str)
        # CSV should have BOM
        assert csv_out.startswith("\ufeff")

    def test_huawei_shadow_detail_roundtrip(self, huawei_complex_cfg):
        """Huawei 复杂配置 → 解析 → 分析 → shadow detail 导出不报错。"""
        from fw_analyzer.analyzers.engine import AnalysisEngine
        parse_result = get_parser("huawei").parse(huawei_complex_cfg)
        analysis = AnalysisEngine().analyze(parse_result)
        exporter = ShadowDetailExporter(config_text=huawei_complex_cfg)
        md = exporter.export_markdown(analysis)
        csv_out = exporter.export_csv(analysis)
        assert isinstance(md, str)
        assert isinstance(csv_out, str)
