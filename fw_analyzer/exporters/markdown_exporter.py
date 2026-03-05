"""
fw_analyzer/exporters/markdown_exporter.py

Markdown 报告导出器。

无 IO 设计：export() 只返回字符串，不写文件。

报告结构：
  # 防火墙规则分析报告
  ## 概览
  ## 解析警告
  ## 分析告警
  ## 规则列表（表格）
  ## 影子规则
  ## 冗余规则
  ## 过宽规则
  ## 合规问题
"""
from __future__ import annotations

from datetime import datetime

from ..analyzers.engine import AnalysisResult
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
        lines.append(f"| 有问题规则 | {result.tagged_rule_count} |")
        lines.append(f"| 解析警告 | {len(result.parse_warnings)} |")
        lines.append(f"| 合规告警 | {len(result.analysis_warnings)} |")
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
            "| # | ID | 名称 | 动作 | 源IP | 目的IP | 服务 | 启用 | 标签 |",
            "|---|----|----|------|------|--------|------|------|------|",
        ]
        for r in rules:
            seq = r.seq + 1
            action_icon = "✅" if r.action == "permit" else "❌"
            enabled_icon = "✓" if r.enabled else "✗"
            tags = r.analysis_tags_str()
            lines.append(
                f"| {seq} | `{r.raw_rule_id}` | {r.rule_name} | "
                f"{action_icon} {r.action} | {_md_escape(r.src_ip_str())} | "
                f"{_md_escape(r.dst_ip_str())} | {_md_escape(r.service_str())} | "
                f"{enabled_icon} | {tags} |"
            )
        return lines

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
