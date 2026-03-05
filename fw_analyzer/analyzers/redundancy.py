"""
fw_analyzer/analyzers/redundancy.py

冗余规则检测。

定义：两条规则完全相同（5元组 + 动作），后出现的规则为冗余规则。

检测方法：O(n) 哈希签名去重。
签名构成：(src_ip_str, dst_ip_str, service_str, action)
"""
from __future__ import annotations

from ..models.rule import FlatRule


class RedundancyAnalyzer:
    """
    冗余规则分析器。

    调用 analyze(rules) 后，重复规则的 analysis_tags 会被原地修改。
    """

    def analyze(self, rules: list[FlatRule]) -> None:
        """
        检测冗余规则，将标签写入 rule.analysis_tags。

        标签格式：
          "REDUNDANT:dup_of={rule_id}"  - 与更早规则完全重复
        """
        seen: dict[str, str] = {}  # signature → first rule_id

        for rule in rules:
            if not rule.enabled:
                continue

            sig = self._signature(rule)
            if sig in seen:
                tag = f"REDUNDANT:dup_of={seen[sig]}"
                if tag not in rule.analysis_tags:
                    rule.analysis_tags.append(tag)
            else:
                seen[sig] = rule.raw_rule_id

    @staticmethod
    def _signature(rule: FlatRule) -> str:
        """
        生成规则的去重签名。

        签名由规范化后的 src_ip、dst_ip、services、action 组成。
        地址和服务先排序再拼接，保证顺序无关。
        """
        src = "|".join(sorted(str(a) for a in rule.src_ip))
        dst = "|".join(sorted(str(a) for a in rule.dst_ip))
        svc = "|".join(sorted(str(s) for s in rule.services))
        return f"{src}::{dst}::{svc}::{rule.action}"
