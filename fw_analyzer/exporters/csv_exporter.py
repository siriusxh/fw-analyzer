"""
fw_analyzer/exporters/csv_exporter.py

CSV 导出器。

无 IO 设计：export() / export_trace() 只返回字符串，不写文件。
IO 操作由 cli.py 最外层完成，方便 Web API 复用。
"""
from __future__ import annotations

import csv
import io

from ..analyzers.engine import AnalysisResult
from ..trace import TraceResult


# CSV 列顺序
RULE_CSV_FIELDS = [
    "seq",
    "rule_id",
    "rule_name",
    "vendor",
    "action",
    "src_ip",
    "dst_ip",
    "protocol",
    "src_port",
    "dst_port",
    "services",
    "src_zone",
    "dst_zone",
    "interface",
    "direction",
    "enabled",
    "log_enabled",
    "comment",
    "ticket",
    "analysis_tags",
    "warnings",
]

TRACE_CSV_FIELDS = [
    "label",
    "src_ip",
    "dst_ip",
    "protocol",
    "src_port",
    "dst_port",
    "matched",
    "matched_rule_id",
    "matched_rule_name",
    "matched_seq",
    "action",
    "match_note",
]


class CsvExporter:
    """CSV 格式导出器。"""

    def export(self, result: AnalysisResult) -> str:
        """
        导出规则列表为 CSV 字符串（含 BOM，方便 Excel 直接打开）。

        Returns:
            CSV 格式字符串
        """
        buf = io.StringIO()
        # 写入 BOM 方便 Excel 识别 UTF-8
        buf.write("\ufeff")

        writer = csv.DictWriter(
            buf,
            fieldnames=RULE_CSV_FIELDS,
            extrasaction="ignore",
            lineterminator="\r\n",
        )
        writer.writeheader()

        for rule in result.rules:
            writer.writerow(rule.to_csv_row())

        return buf.getvalue()

    def export_trace(self, results: list[TraceResult]) -> str:
        """
        导出 Trace 结果为 CSV 字符串。

        Returns:
            CSV 格式字符串
        """
        buf = io.StringIO()
        buf.write("\ufeff")

        writer = csv.DictWriter(
            buf,
            fieldnames=TRACE_CSV_FIELDS,
            extrasaction="ignore",
            lineterminator="\r\n",
        )
        writer.writeheader()

        for tr in results:
            writer.writerow(tr.to_csv_row())

        return buf.getvalue()
