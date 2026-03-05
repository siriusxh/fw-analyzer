"""
tests/conftest.py

pytest 共用夹具：加载各厂商的示例配置文件内容。
"""
from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def huawei_cfg() -> str:
    """华为 USG 示例配置文本。"""
    return (FIXTURES_DIR / "huawei_simple.cfg").read_text(encoding="utf-8")


@pytest.fixture
def cisco_cfg() -> str:
    """Cisco ASA 示例配置文本。"""
    return (FIXTURES_DIR / "cisco_asa_simple.cfg").read_text(encoding="utf-8")


@pytest.fixture
def paloalto_cfg() -> str:
    """PAN-OS XML 示例配置文本。"""
    return (FIXTURES_DIR / "paloalto_simple.xml").read_text(encoding="utf-8")


@pytest.fixture
def fortinet_cfg() -> str:
    """FortiGate 示例配置文本。"""
    return (FIXTURES_DIR / "fortinet_simple.cfg").read_text(encoding="utf-8")
