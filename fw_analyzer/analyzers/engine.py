"""
fw_analyzer/analyzers/engine.py

分析引擎：统一调度所有分析器。

使用方式：
  engine = AnalysisEngine(config)
  result = engine.analyze(parse_result)
  # result.rules 中已包含分析标签
  # result.warnings 中包含文件级别的合规告警
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..models.rule import FlatRule, Warning, ParseResult
from ..config import AnalyzerConfig
from .shadow import ShadowAnalyzer
from .redundancy import RedundancyAnalyzer
from .overwidth import OverwidthAnalyzer
from .compliance import ComplianceAnalyzer


@dataclass
class AnalysisResult:
    """
    分析结果：包含打了标签的规则列表和全局告警。
    """
    rules: list[FlatRule]
    parse_warnings: list[Warning]       # 来自解析阶段的警告
    analysis_warnings: list[Warning]    # 来自分析阶段（合规）的告警
    vendor: str
    source_file: str

    @property
    def all_warnings(self) -> list[Warning]:
        return self.parse_warnings + self.analysis_warnings

    @property
    def rule_count(self) -> int:
        return len(self.rules)

    @property
    def tagged_rule_count(self) -> int:
        return sum(1 for r in self.rules if r.analysis_tags)

    def to_dict(self) -> dict:
        return {
            "vendor": self.vendor,
            "source_file": self.source_file,
            "rule_count": self.rule_count,
            "tagged_rule_count": self.tagged_rule_count,
            "parse_warnings": [w.to_dict() for w in self.parse_warnings],
            "analysis_warnings": [w.to_dict() for w in self.analysis_warnings],
            "rules": [r.to_dict() for r in self.rules],
        }


class AnalysisEngine:
    """
    防火墙规则分析引擎。

    按顺序执行：影子 → 冗余 → 过宽 → 合规。
    """

    def __init__(self, config: AnalyzerConfig | None = None) -> None:
        self.config = config or AnalyzerConfig()
        self._shadow = ShadowAnalyzer()
        self._redundancy = RedundancyAnalyzer()
        self._overwidth = OverwidthAnalyzer()
        self._compliance = ComplianceAnalyzer()

    def analyze(self, parse_result: ParseResult) -> AnalysisResult:
        """
        对 ParseResult 执行全量分析，返回 AnalysisResult。

        parse_result.rules 中的 FlatRule 对象会被原地修改（写入 analysis_tags）。
        """
        rules = parse_result.rules

        # 1. 影子规则
        self._shadow.analyze(rules)

        # 2. 冗余规则
        self._redundancy.analyze(rules)

        # 3. 过宽规则
        self._overwidth.analyze(rules, self.config)

        # 4. 合规检查（同时返回文件级别告警）
        analysis_warnings = self._compliance.analyze(rules, self.config)

        return AnalysisResult(
            rules=rules,
            parse_warnings=parse_result.warnings,
            analysis_warnings=analysis_warnings,
            vendor=parse_result.vendor,
            source_file=parse_result.source_file,
        )
