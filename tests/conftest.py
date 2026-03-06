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


# ------------------------------------------------------------------
# 复杂 fixture（嵌套对象组、FQDN、非连续 Wildcard、禁用规则）
# ------------------------------------------------------------------


@pytest.fixture
def huawei_complex_cfg() -> str:
    """华为 USG 复杂配置文本（嵌套地址组 + ACL 非连续 wildcard + 禁用规则）。"""
    return (FIXTURES_DIR / "huawei_complex.cfg").read_text(encoding="utf-8")


@pytest.fixture
def cisco_complex_cfg() -> str:
    """Cisco ASA 复杂配置文本（4层嵌套 object-group + FQDN）。"""
    return (FIXTURES_DIR / "cisco_asa_complex.cfg").read_text(encoding="utf-8")


@pytest.fixture
def paloalto_complex_cfg() -> str:
    """PAN-OS XML 复杂配置文本（嵌套 address-group + FQDN + 禁用规则）。"""
    return (FIXTURES_DIR / "paloalto_complex.xml").read_text(encoding="utf-8")


@pytest.fixture
def fortinet_complex_cfg() -> str:
    """FortiGate 复杂配置文本（嵌套 addrgrp + FQDN + wildcard-fqdn + 禁用规则）。"""
    return (FIXTURES_DIR / "fortinet_complex.cfg").read_text(encoding="utf-8")


@pytest.fixture
def paloalto_set_cfg() -> str:
    """PAN-OS set 命令格式示例配置文本。"""
    return (FIXTURES_DIR / "paloalto_set_simple.cfg").read_text(encoding="utf-8")


@pytest.fixture
def paloalto_set_complex_cfg() -> str:
    """PAN-OS set 命令格式复杂配置文本（嵌套组 + FQDN + IP字面量 + 引号名称）。"""
    return (FIXTURES_DIR / "paloalto_set_complex.cfg").read_text(encoding="utf-8")
