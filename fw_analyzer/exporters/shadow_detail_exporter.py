"""
fw_analyzer/exporters/shadow_detail_exporter.py

Shadow 详细报告导出器（Markdown + CSV）。

无 IO 设计：export_markdown() / export_csv() 只返回字符串，不写文件。
IO 操作由 cli.py 最外层完成。

报告内容：
  - 每组 shadower → victim(s) 关系输出一个段落
  - 包含规则摘要表格、原始配置命令、引用对象定义
"""
from __future__ import annotations

import csv
import io
import re
from collections import defaultdict

from ..analyzers.engine import AnalysisResult
from ..models.rule import FlatRule
from .raw_text_extractor import RawTextExtractor


# CSV 列定义（12 列）
SHADOW_DETAIL_CSV_FIELDS = [
    "shadower_id",
    "shadower_seq",
    "shadower_desc",
    "shadower_raw_config",
    "shadower_objects",
    "shadow_type",
    "victim_id",
    "victim_seq",
    "victim_desc",
    "victim_raw_config",
    "victim_objects",
    "victim_other_tags",
]


def _rule_desc(rule: FlatRule) -> str:
    """生成规则的合并摘要字段。

    格式：action | src_ip | dst_ip | service | zone | ticket
    """
    parts = [
        rule.action.upper(),
        rule.src_ip_str(),
        rule.dst_ip_str(),
        rule.service_str() or "any",
    ]
    zone_str = ""
    if rule.src_zone or rule.dst_zone:
        zone_str = f"{rule.src_zone or '*'} → {rule.dst_zone or '*'}"
    elif rule.interface:
        zone_str = rule.interface
    if zone_str:
        parts.append(zone_str)
    if rule.ticket:
        parts.append(rule.ticket)
    return " | ".join(parts)


def _extract_objects_text(
    rule: FlatRule, config_text: str, extractor: RawTextExtractor,
) -> str:
    """提取规则引用的所有对象定义，用 || 分隔不同对象。"""
    if not rule.referenced_objects or not config_text:
        return ""
    obj_defs = extractor.extract(rule.vendor, config_text, rule.referenced_objects)
    if not obj_defs:
        return ""
    return " || ".join(obj_defs.values())


def _build_shadow_pairs(
    result: AnalysisResult,
) -> list[tuple[FlatRule, str, FlatRule]]:
    """从 AnalysisResult 中提取所有 (shadower, shadow_type, victim) 三元组。

    遍历所有规则，找出含 SHADOW:by= / SHADOW_CONFLICT:by= 标签的 victim 规则，
    然后反查 shadower 规则。按 shadower.seq 排序。
    """
    # 建立 raw_rule_id → FlatRule 索引
    id_to_rule: dict[str, FlatRule] = {}
    for rule in result.rules:
        id_to_rule[rule.raw_rule_id] = rule

    pairs: list[tuple[FlatRule, str, FlatRule]] = []

    for victim in result.rules:
        for tag in victim.analysis_tags:
            # SHADOW:by=<id> 或 SHADOW_CONFLICT:by=<id>
            m = re.match(r"(SHADOW|SHADOW_CONFLICT):by=(.+)$", tag)
            if not m:
                continue
            shadow_type = m.group(1)
            shadower_id = m.group(2)
            shadower = id_to_rule.get(shadower_id)
            if shadower:
                pairs.append((shadower, shadow_type, victim))

    # 按 shadower.seq 排序，使相同 shadower 的 pair 连续
    pairs.sort(key=lambda t: (t[0].seq, t[2].seq))
    return pairs


class ShadowDetailExporter:
    """Shadow 详细报告导出器。"""

    def __init__(self, config_text: str = "") -> None:
        """
        Args:
            config_text: 完整的原始防火墙配置文本，用于提取对象定义。
        """
        self._config_text = config_text
        self._extractor = RawTextExtractor()

    # ------------------------------------------------------------------
    # Markdown 导出
    # ------------------------------------------------------------------

    def export_markdown(self, result: AnalysisResult) -> str:
        """导出 Shadow 详细报告（Markdown 格式）。

        结构：
          # Shadow Detail Report
          ## 1. [Shadower] <shadower_id> (seq=N)
            摘要表格
            原始配置
            引用对象
          ### 1.1 [Victim] <victim_id> (seq=N) — SHADOW
            摘要表格
            原始配置
            引用对象
        """
        pairs = _build_shadow_pairs(result)
        if not pairs:
            return f"# Shadow Detail Report — {result.source_file}\n\n*No shadow relationships found.*\n"

        lines: list[str] = []
        lines.append(f"# Shadow Detail Report — {result.source_file}")
        lines.append("")
        lines.append(f"Vendor: **{result.vendor}** | Total rules: **{result.rule_count}** "
                      f"| Shadow pairs: **{len(pairs)}**")
        lines.append("")

        # 按 shadower 分组
        grouped: dict[str, list[tuple[FlatRule, str, FlatRule]]] = defaultdict(list)
        group_order: list[str] = []
        for shadower, stype, victim in pairs:
            key = shadower.raw_rule_id
            if key not in grouped:
                group_order.append(key)
            grouped[key].append((shadower, stype, victim))

        for group_idx, shadower_id in enumerate(group_order, 1):
            group = grouped[shadower_id]
            shadower = group[0][0]

            lines.append("---")
            lines.append("")
            lines.append(f"## {group_idx}. [Shadower] {shadower.raw_rule_id} (seq={shadower.seq})")
            lines.append("")

            # 摘要表格
            lines.extend(self._md_rule_table(shadower))
            lines.append("")

            # 原始配置
            if shadower.raw_config:
                lines.append("**Original Config:**")
                lines.append("")
                lines.append("```")
                lines.append(shadower.raw_config)
                lines.append("```")
                lines.append("")

            # 引用对象
            obj_text = self._get_object_defs_md(shadower)
            if obj_text:
                lines.append("**Referenced Objects:**")
                lines.append("")
                lines.append("```")
                lines.append(obj_text)
                lines.append("```")
                lines.append("")

            # 各 victim
            for victim_idx, (_, stype, victim) in enumerate(group, 1):
                lines.append(
                    f"### {group_idx}.{victim_idx} [Victim] "
                    f"{victim.raw_rule_id} (seq={victim.seq}) — {stype}"
                )
                lines.append("")

                lines.extend(self._md_rule_table(victim))
                lines.append("")

                if victim.raw_config:
                    lines.append("**Original Config:**")
                    lines.append("")
                    lines.append("```")
                    lines.append(victim.raw_config)
                    lines.append("```")
                    lines.append("")

                victim_obj = self._get_object_defs_md(victim)
                if victim_obj:
                    lines.append("**Referenced Objects:**")
                    lines.append("")
                    lines.append("```")
                    lines.append(victim_obj)
                    lines.append("```")
                    lines.append("")

                # victim 的其他（非 shadow）分析标签
                other_tags = victim.non_shadow_tags()
                if other_tags:
                    lines.append(f"*Other tags: {' | '.join(other_tags)}*")
                    lines.append("")

        return "\n".join(lines)

    def _md_rule_table(self, rule: FlatRule) -> list[str]:
        """生成规则摘要的 Markdown 表格。"""
        zone_str = ""
        if rule.src_zone or rule.dst_zone:
            zone_str = f"{rule.src_zone or '*'} → {rule.dst_zone or '*'}"
        elif rule.interface:
            zone_str = rule.interface

        rows = [
            ("Action", rule.action.upper()),
            ("Source", rule.src_ip_str()),
            ("Destination", rule.dst_ip_str()),
            ("Service", rule.service_str() or "any"),
            ("Zone/Interface", zone_str or "—"),
            ("Ticket", rule.ticket or "—"),
            ("Enabled", "Yes" if rule.enabled else "No"),
        ]
        lines = [
            "| Field | Value |",
            "|-------|-------|",
        ]
        for field_name, value in rows:
            # 在 Markdown 表格中转义 pipe
            safe_value = value.replace("|", "\\|")
            lines.append(f"| {field_name} | {safe_value} |")
        return lines

    def _get_object_defs_md(self, rule: FlatRule) -> str:
        """提取规则引用的对象定义文本，用空行分隔不同对象。"""
        if not rule.referenced_objects or not self._config_text:
            return ""
        obj_defs = self._extractor.extract(
            rule.vendor, self._config_text, rule.referenced_objects,
        )
        if not obj_defs:
            return ""
        return "\n\n".join(obj_defs.values())

    # ------------------------------------------------------------------
    # CSV 导出
    # ------------------------------------------------------------------

    def export_csv(self, result: AnalysisResult) -> str:
        """导出 Shadow 详细报告（CSV 格式，12 列）。

        每个 shadower-victim pair 一行。

        Returns:
            CSV 字符串（含 BOM）
        """
        pairs = _build_shadow_pairs(result)

        buf = io.StringIO()
        buf.write("\ufeff")  # BOM for Excel

        writer = csv.DictWriter(
            buf,
            fieldnames=SHADOW_DETAIL_CSV_FIELDS,
            extrasaction="ignore",
            lineterminator="\r\n",
        )
        writer.writeheader()

        for shadower, shadow_type, victim in pairs:
            shadower_objs = _extract_objects_text(
                shadower, self._config_text, self._extractor,
            )
            victim_objs = _extract_objects_text(
                victim, self._config_text, self._extractor,
            )

            writer.writerow({
                "shadower_id": shadower.raw_rule_id,
                "shadower_seq": shadower.seq,
                "shadower_desc": _rule_desc(shadower),
                "shadower_raw_config": _pipe_lines(shadower.raw_config),
                "shadower_objects": shadower_objs,
                "shadow_type": shadow_type,
                "victim_id": victim.raw_rule_id,
                "victim_seq": victim.seq,
                "victim_desc": _rule_desc(victim),
                "victim_raw_config": _pipe_lines(victim.raw_config),
                "victim_objects": victim_objs,
                "victim_other_tags": " | ".join(victim.non_shadow_tags()),
            })

        return buf.getvalue()


def _pipe_lines(text: str) -> str:
    """将多行文本转为 pipe 分隔的单行（用于 CSV 字段）。"""
    if not text:
        return ""
    return " | ".join(line.strip() for line in text.splitlines() if line.strip())
