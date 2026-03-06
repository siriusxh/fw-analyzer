"""
fw_analyzer/exporters/markdown_exporter.py

Markdown 报告导出器。

无 IO 设计：export() 只返回字符串，不写文件。

报告结构：
  # 防火墙规则分析报告
  ## 概览
  ## 标签分类统计
  ## 解析警告
  ## 分析告警
  ## 规则列表（表格）
  ## 影子规则
  ## 冗余规则
  ## 过宽规则
  ## 合规问题
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime

from ..analyzers.engine import AnalysisResult, _is_informational
from ..models.rule import FlatRule
from ..trace import TraceResult


class MarkdownExporter:
    """Markdown 格式报告导出器。"""

    def export(self, result: AnalysisResult) -> str:
        """
        生成 Markdown 格式的分析报告。

        Returns:
            Markdown 格式字符串
        """
        lines: list[str] = []

        # 标题
        lines.append("# 防火墙规则分析报告")
        lines.append("")
        lines.append(f"- **文件**: `{result.source_file}`")
        lines.append(f"- **厂商**: {result.vendor}")
        lines.append(f"- **生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")

        # 概览
        lines.append("## 概览")
        lines.append("")
        lines.append(f"| 指标 | 数值 |")
        lines.append(f"|------|------|")
        lines.append(f"| 规则总数 | {result.rule_count} |")
        lines.append(f"| 启用规则 | {sum(1 for r in result.rules if r.enabled)} |")
        lines.append(f"| 禁用规则 | {sum(1 for r in result.rules if not r.enabled)} |")
        lines.append(f"| 问题规则 | {result.issue_rule_count} |")
        lines.append(f"| 信息性标记 | {result.info_rule_count} |")
        lines.append(f"| 解析警告 | {len(result.parse_warnings)} |")
        lines.append(f"| 合规告警 | {len(result.analysis_warnings)} |")
        lines.append("")

        # 标签分类统计
        tag_lines = self._tag_breakdown(result)
        if tag_lines:
            lines.extend(tag_lines)
            lines.append("")

        # 解析警告
        if result.parse_warnings:
            lines.append("## 解析警告")
            lines.append("")
            for w in result.parse_warnings:
                lines.append(f"- **[{w.severity.value.upper()}]** `{w.code}`: {w.message}")
            lines.append("")

        # 合规告警
        if result.analysis_warnings:
            lines.append("## 合规告警")
            lines.append("")
            for w in result.analysis_warnings:
                lines.append(f"- **[{w.severity.value.upper()}]** `{w.code}`: {w.message}")
            lines.append("")

        # 规则列表
        lines.append("## 规则列表")
        lines.append("")
        lines.extend(self._rules_table(result.rules))
        lines.append("")

        # 问题规则分类
        shadow = [r for r in result.rules if any("SHADOW" in t for t in r.analysis_tags)]
        redundant = [r for r in result.rules if any("REDUNDANT" in t for t in r.analysis_tags)]
        overwide = [r for r in result.rules if any("OVERWIDE" in t for t in r.analysis_tags)]
        compliance = [r for r in result.rules if any("COMPLIANCE" in t for t in r.analysis_tags)]

        if shadow:
            lines.append("## 影子规则")
            lines.append("")
            lines.append(f"> 共 {len(shadow)} 条规则被更早的规则完全覆盖。")
            lines.append("")
            for r in shadow:
                tags = [t for t in r.analysis_tags if "SHADOW" in t]
                lines.append(f"- **#{r.seq + 1}** `{r.rule_name}` ({r.raw_rule_id}): {', '.join(tags)}")
            lines.append("")

        if redundant:
            lines.append("## 冗余规则")
            lines.append("")
            lines.append(f"> 共 {len(redundant)} 条规则与更早的规则完全重复。")
            lines.append("")
            for r in redundant:
                tags = [t for t in r.analysis_tags if "REDUNDANT" in t]
                lines.append(f"- **#{r.seq + 1}** `{r.rule_name}` ({r.raw_rule_id}): {', '.join(tags)}")
            lines.append("")

        if overwide:
            lines.append("## 过宽规则")
            lines.append("")
            lines.append(f"> 共 {len(overwide)} 条规则存在过宽访问风险。")
            lines.append("")
            for r in overwide:
                tags = [t for t in r.analysis_tags if "OVERWIDE" in t]
                lines.append(
                    f"- **#{r.seq + 1}** `{r.rule_name}` ({r.raw_rule_id}): {', '.join(tags)}"
                    f" | src={r.src_ip_str()} | dst={r.dst_ip_str()} | svc={r.service_str()}"
                )
            lines.append("")

        if compliance:
            lines.append("## 合规问题")
            lines.append("")
            lines.append(f"> 共 {len(compliance)} 条规则存在合规问题。")
            lines.append("")
            for r in compliance:
                tags = [t for t in r.analysis_tags if "COMPLIANCE" in t]
                lines.append(f"- **#{r.seq + 1}** `{r.rule_name}` ({r.raw_rule_id}): {', '.join(tags)}")
            lines.append("")

        return "\n".join(lines)

    def _rules_table(self, rules: list[FlatRule]) -> list[str]:
        """生成规则列表 Markdown 表格。"""
        lines = [
            "| # | ID | 名称 | 动作 | 源IP | 目的IP | 服务 | 启用 | 日志 | 工单号 | 标签 |",
            "|---|----|----|------|------|--------|------|------|------|--------|------|",
        ]
        for r in rules:
            seq = r.seq + 1
            action_icon = "✅" if r.action == "permit" else "❌"
            enabled_icon = "✓" if r.enabled else "✗"
            log_icon = "✓" if r.log_enabled else "✗"
            tags = r.analysis_tags_str()
            ticket = r.ticket or "-"
            lines.append(
                f"| {seq} | `{r.raw_rule_id}` | {r.rule_name} | "
                f"{action_icon} {r.action} | {_md_escape(r.src_ip_str())} | "
                f"{_md_escape(r.dst_ip_str())} | {_md_escape(r.service_str())} | "
                f"{enabled_icon} | {log_icon} | {ticket} | {tags} |"
            )
        return lines

    def _tag_breakdown(self, result: AnalysisResult) -> list[str]:
        """
        生成标签分类统计表。

        统计每种标签的命中规则数，按类别分组：
          - 质量问题：SHADOW、SHADOW_CONFLICT、REDUNDANT
          - 过宽风险：OVERWIDE:*
          - 合规问题（问题类）：NO_TICKET、NO_LOG、PERMIT_ANY_ANY、CLEARTEXT、HIGH_RISK_PORT
          - 合规信息（信息类）：NO_COMMENT、DISABLED_RULES
        """
        # 收集所有标签，归一化统计（带参数的标签如 CLEARTEXT:port=23 归为 CLEARTEXT）
        tag_counter: Counter[str] = Counter()
        for rule in result.rules:
            seen: set[str] = set()  # 每条规则同类标签只计一次
            for tag in rule.analysis_tags:
                normalized = self._normalize_tag(tag)
                if normalized not in seen:
                    seen.add(normalized)
                    tag_counter[normalized] += 1

        if not tag_counter:
            return []

        lines: list[str] = []
        lines.append("## 标签分类统计")
        lines.append("")
        lines.append("| 类别 | 标签 | 规则数 | 性质 |")
        lines.append("|------|------|--------|------|")

        # 定义标签展示顺序和分类
        tag_groups: list[tuple[str, list[tuple[str, str]]]] = [
            ("质量问题", [
                ("SHADOW", "SHADOW"),
                ("SHADOW_CONFLICT", "SHADOW_CONFLICT"),
                ("REDUNDANT", "REDUNDANT"),
            ]),
            ("过宽风险", [
                ("OVERWIDE:CRITICAL", "OVERWIDE:CRITICAL"),
                ("OVERWIDE:HIGH", "OVERWIDE:HIGH"),
                ("OVERWIDE:MEDIUM", "OVERWIDE:MEDIUM"),
                ("OVERWIDE:LOW", "OVERWIDE:LOW"),
            ]),
            ("合规问题", [
                ("COMPLIANCE:PERMIT_ANY_ANY", "COMPLIANCE:PERMIT_ANY_ANY"),
                ("COMPLIANCE:CLEARTEXT", "COMPLIANCE:CLEARTEXT"),
                ("COMPLIANCE:HIGH_RISK_PORT", "COMPLIANCE:HIGH_RISK_PORT"),
                ("COMPLIANCE:NO_TICKET", "COMPLIANCE:NO_TICKET"),
                ("COMPLIANCE:NO_LOG", "COMPLIANCE:NO_LOG"),
            ]),
            ("合规信息", [
                ("COMPLIANCE:NO_COMMENT", "COMPLIANCE:NO_COMMENT"),
                ("COMPLIANCE:DISABLED_RULES", "COMPLIANCE:DISABLED_RULES"),
            ]),
        ]

        for category, tags in tag_groups:
            for display_name, tag_key in tags:
                count = tag_counter.get(tag_key, 0)
                if count == 0:
                    continue
                nature = "信息" if _is_informational(tag_key) else "问题"
                lines.append(f"| {category} | `{display_name}` | {count} | {nature} |")

        # 检查是否有未在上述分类中的标签（防御性编程）
        known_tags = {tag_key for _, tags in tag_groups for _, tag_key in tags}
        for tag_key, count in sorted(tag_counter.items()):
            if tag_key not in known_tags:
                nature = "信息" if _is_informational(tag_key) else "问题"
                lines.append(f"| 其他 | `{tag_key}` | {count} | {nature} |")

        return lines

    @staticmethod
    def _normalize_tag(tag: str) -> str:
        """
        归一化标签名用于统计。

        带参数的标签（如 COMPLIANCE:CLEARTEXT:port=23）归一化为基础标签
        （COMPLIANCE:CLEARTEXT），SHADOW:by=rule-0 归一化为 SHADOW。
        """
        # SHADOW:by=xxx → SHADOW
        if tag.startswith("SHADOW:by="):
            return "SHADOW"
        # SHADOW_CONFLICT:by=xxx → SHADOW_CONFLICT
        if tag.startswith("SHADOW_CONFLICT:by="):
            return "SHADOW_CONFLICT"
        # REDUNDANT:dup_of=xxx → REDUNDANT
        if tag.startswith("REDUNDANT:dup_of="):
            return "REDUNDANT"
        # COMPLIANCE:CLEARTEXT:port=23 → COMPLIANCE:CLEARTEXT
        if tag.startswith("COMPLIANCE:CLEARTEXT:"):
            return "COMPLIANCE:CLEARTEXT"
        # COMPLIANCE:HIGH_RISK_PORT:port=22 → COMPLIANCE:HIGH_RISK_PORT
        if tag.startswith("COMPLIANCE:HIGH_RISK_PORT:"):
            return "COMPLIANCE:HIGH_RISK_PORT"
        # OVERWIDE:CRITICAL, OVERWIDE:HIGH etc. — already normalized
        return tag

    def export_trace(self, results: list[TraceResult]) -> str:
        """
        生成 Trace 结果的 Markdown 报告。

        Returns:
            Markdown 格式字符串
        """
        lines: list[str] = []
        lines.append("# 访问需求 Trace 分析报告")
        lines.append("")
        lines.append(f"- **生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"- **查询条数**: {len(results)}")
        lines.append("")

        hit = sum(1 for r in results if r.matched)
        miss = len(results) - hit
        lines.append(f"| 命中 | 未命中 |")
        lines.append(f"|------|--------|")
        lines.append(f"| {hit} | {miss} |")
        lines.append("")

        lines.append("## 详细结果")
        lines.append("")
        lines.append("| # | 标签 | 源IP | 目的IP | 协议 | 目的端口 | 命中 | 规则 | 动作 | 说明 |")
        lines.append("|---|------|------|--------|------|----------|------|------|------|------|")

        for i, tr in enumerate(results, 1):
            q = tr.query
            matched = "✓" if tr.matched else "✗"
            rule_info = f"`{tr.matched_rule.raw_rule_id}` {tr.matched_rule.rule_name}" \
                if tr.matched_rule else "-"
            lines.append(
                f"| {i} | {q.label or '-'} | {q.src_ip} | {q.dst_ip} | "
                f"{q.protocol} | {q.dst_port or 'any'} | {matched} | "
                f"{rule_info} | {tr.action} | {tr.match_note or ''} |"
            )

        lines.append("")
        return "\n".join(lines)


def _md_escape(text: str) -> str:
    """转义 Markdown 表格中的特殊字符。"""
    return text.replace("|", "\\|")
