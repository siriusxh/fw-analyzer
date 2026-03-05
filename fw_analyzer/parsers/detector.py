"""
fw_analyzer/parsers/detector.py

厂商自动识别模块。

通过检测配置文件的特征字符串和文件扩展名来判断厂商类型。
返回的厂商标识符与 VENDOR_PARSERS 中的 key 一致。
"""
from __future__ import annotations

import re


# 各厂商的特征检测规则（按优先级排序）
_VENDOR_SIGNATURES: list[tuple[str, list[str]]] = [
    # Palo Alto：XML 结构特征
    ("paloalto", [
        r"<config\s+version=",
        r"<devices>.*<entry\s+name=",
        r"<security>.*<rules>",
        r"xmlns.*paloaltonetworks",
    ]),
    # Cisco ASA：ASA 特有关键字
    ("cisco-asa", [
        r"^ASA\s+Version\s+",
        r"^access-list\s+\S+\s+extended\s+(permit|deny)",
        r"^object-group\s+(network|service|icmp-type)",
        r"^object\s+(network|service)\s+",
        r"^nameif\s+",
        r"^security-level\s+",
    ]),
    # 华为：华为防火墙特有关键字
    ("huawei", [
        r"^firewall\s+policy\s+interzone",
        r"^security-policy$",
        r"^\s+rule\s+name\s+",
        r"^ip\s+address-group\s+",
        r"^firewall\s+zone\s+",
        r"Huawei\s+(Versatile|USG|NE)",
        r"^acl\s+(number|name)\s+",
    ]),
    # Fortinet：FortiGate 特有关键字
    ("fortinet", [
        r"^config\s+firewall\s+policy$",
        r"^config\s+firewall\s+address$",
        r"^config\s+firewall\s+addrgrp$",
        r"^config\s+firewall\s+service",
        r"FortiGate",
        r"FortiOS",
        r"^\s+set\s+srcaddr\s+",
    ]),
]


def detect_vendor(text: str, filename: str = "") -> str:
    """
    通过启发式规则识别防火墙配置的厂商。

    检测策略（按优先级）：
      1. 文件扩展名 .xml → 候选 paloalto（仍需内容验证）
      2. 逐条检测特征正则，命中数最多的厂商获胜
      3. 无法识别时返回 "unknown"

    Args:
        text:     配置文件文本内容
        filename: 原始文件名（可选，用于扩展名检测）

    Returns:
        厂商标识符："huawei" / "cisco-asa" / "paloalto" / "fortinet" / "unknown"
    """
    if not text or not text.strip():
        return "unknown"

    # 扩展名提示
    ext_hint: str | None = None
    if filename:
        lower_name = filename.lower()
        if lower_name.endswith(".xml"):
            ext_hint = "paloalto"

    # 计算每个厂商的特征命中数
    scores: dict[str, int] = {}
    for vendor, patterns in _VENDOR_SIGNATURES:
        score = 0
        for pattern in patterns:
            if re.search(pattern, text, re.MULTILINE | re.IGNORECASE):
                score += 1
        if score > 0:
            scores[vendor] = score

    if not scores:
        # 无任何特征命中，用扩展名提示
        return ext_hint or "unknown"

    # 选命中数最多的厂商
    best_vendor = max(scores, key=lambda v: scores[v])

    # 如果扩展名提示 paloalto 且有命中，优先采纳
    if ext_hint == "paloalto" and "paloalto" in scores:
        return "paloalto"

    return best_vendor


def detect_vendor_with_confidence(
    text: str,
    filename: str = "",
) -> tuple[str, float]:
    """
    返回厂商识别结果及置信度（0.0 ~ 1.0）。

    置信度计算：命中特征数 / 该厂商总特征数。
    供 CLI 的 detect 子命令展示详细信息使用。
    """
    if not text or not text.strip():
        return "unknown", 0.0

    best_vendor = detect_vendor(text, filename)
    if best_vendor == "unknown":
        return "unknown", 0.0

    # 找到对应厂商的总特征数
    for vendor, patterns in _VENDOR_SIGNATURES:
        if vendor == best_vendor:
            matched = sum(
                1 for p in patterns
                if re.search(p, text, re.MULTILINE | re.IGNORECASE)
            )
            confidence = matched / len(patterns)
            return best_vendor, round(confidence, 2)

    return best_vendor, 0.5
