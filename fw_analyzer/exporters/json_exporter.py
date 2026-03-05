"""
fw_analyzer/exporters/json_exporter.py

JSON 导出器。

无 IO 设计：export() 只返回字符串，不写文件。
"""
from __future__ import annotations

import json

from ..analyzers.engine import AnalysisResult
from ..trace import TraceResult


class JsonExporter:
    """JSON 格式导出器。"""

    def export(self, result: AnalysisResult, indent: int = 2) -> str:
        """
        导出分析结果为 JSON 字符串。

        Args:
            result: AnalysisResult
            indent: JSON 缩进（默认 2 空格）

        Returns:
            JSON 格式字符串
        """
        data = result.to_dict()
        return json.dumps(data, ensure_ascii=False, indent=indent)

    def export_trace(
        self,
        results: list[TraceResult],
        indent: int = 2,
    ) -> str:
        """
        导出 Trace 结果为 JSON 字符串。

        Returns:
            JSON 格式字符串
        """
        data = [tr.to_dict() for tr in results]
        return json.dumps(data, ensure_ascii=False, indent=indent)
