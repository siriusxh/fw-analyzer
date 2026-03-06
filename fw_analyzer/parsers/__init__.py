"""
fw_analyzer/parsers/__init__.py
"""
from .base import AbstractParser, ParseError
from .detector import detect_vendor
from .huawei import HuaweiParser
from .cisco_asa import CiscoAsaParser
from .palo_alto import PaloAltoParser
from .palo_alto_set import PaloAltoSetParser
from .fortinet import FortinetParser

VENDOR_PARSERS: dict[str, type[AbstractParser]] = {
    "huawei": HuaweiParser,
    "cisco-asa": CiscoAsaParser,
    "paloalto": PaloAltoParser,
    "paloalto-set": PaloAltoSetParser,
    "fortinet": FortinetParser,
}


def get_parser(vendor: str) -> AbstractParser:
    """
    根据厂商名称返回对应的 Parser 实例。

    Args:
        vendor: "huawei" / "cisco-asa" / "paloalto" / "paloalto-set" / "fortinet" / "auto"

    Raises:
        ValueError: 不支持的厂商名称
    """
    key = vendor.lower()
    if key not in VENDOR_PARSERS:
        raise ValueError(
            f"不支持的厂商: {vendor!r}，"
            f"支持的厂商: {list(VENDOR_PARSERS.keys())}"
        )
    return VENDOR_PARSERS[key]()


__all__ = [
    "AbstractParser",
    "ParseError",
    "detect_vendor",
    "HuaweiParser",
    "CiscoAsaParser",
    "PaloAltoParser",
    "PaloAltoSetParser",
    "FortinetParser",
    "VENDOR_PARSERS",
    "get_parser",
]
