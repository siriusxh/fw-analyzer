"""
tests/test_config.py

配置加载（TOML）与默认值回退测试。
"""
from __future__ import annotations

import os
import pytest
from pathlib import Path
from unittest.mock import patch

from fw_analyzer.config import (
    AnalyzerConfig,
    ComplianceConfig,
    OverwideConfig,
    load_config,
    DEFAULT_HIGH_RISK_TCP_PORTS,
    DEFAULT_HIGH_RISK_UDP_PORTS,
)


# ======================================================================
# TestAnalyzerConfig
# ======================================================================


class TestAnalyzerConfig:
    """AnalyzerConfig 数据类与方法测试。"""

    def test_default_high_risk_ports(self):
        """默认高危端口列表非空。"""
        cfg = AnalyzerConfig()
        assert len(cfg.high_risk_tcp_ports) > 0
        assert len(cfg.high_risk_udp_ports) > 0
        assert 23 in cfg.high_risk_tcp_ports  # Telnet
        assert 53 in cfg.high_risk_udp_ports  # DNS

    def test_is_high_risk_tcp(self):
        cfg = AnalyzerConfig()
        assert cfg.is_high_risk("tcp", 23) is True    # Telnet
        assert cfg.is_high_risk("tcp", 443) is False   # HTTPS 不是高危

    def test_is_high_risk_udp(self):
        cfg = AnalyzerConfig()
        assert cfg.is_high_risk("udp", 161) is True   # SNMP
        assert cfg.is_high_risk("udp", 443) is False

    def test_is_high_risk_tcp_udp(self):
        """tcp-udp 协议同时检查两个列表。"""
        cfg = AnalyzerConfig()
        assert cfg.is_high_risk("tcp-udp", 53) is True  # DNS 在两个列表中

    def test_is_high_risk_unknown_proto(self):
        cfg = AnalyzerConfig()
        assert cfg.is_high_risk("icmp", 23) is False

    def test_overwide_get_severity(self):
        ow = OverwideConfig()
        assert ow.get_severity(22) == "CRITICAL"
        assert ow.get_severity(3306) == "HIGH"
        assert ow.get_severity(161) == "MEDIUM"
        assert ow.get_severity(69) == "LOW"
        assert ow.get_severity(9999) is None

    def test_compliance_defaults(self):
        """合规检查开关默认全部为 True。"""
        cc = ComplianceConfig()
        assert cc.check_permit_any_any is True
        assert cc.check_no_implicit_deny is True
        assert cc.check_cleartext is True
        assert cc.check_high_risk_ports is True
        assert cc.check_no_comment is True
        assert cc.check_disabled_rules is True


# ======================================================================
# TestLoadConfig
# ======================================================================


class TestLoadConfig:
    """load_config 配置加载优先级与降级测试。"""

    def test_no_file_returns_default(self, tmp_path, monkeypatch):
        """无配置文件时返回默认值。"""
        monkeypatch.chdir(tmp_path)
        cfg = load_config()
        assert isinstance(cfg, AnalyzerConfig)
        assert cfg.high_risk_tcp_ports == DEFAULT_HIGH_RISK_TCP_PORTS

    def test_explicit_path(self, tmp_path):
        """显式路径加载。"""
        toml_file = tmp_path / "test.toml"
        toml_file.write_text(
            '[high_risk_ports]\ntcp = [22, 23]\nudp = [53]\n',
            encoding="utf-8",
        )
        cfg = load_config(str(toml_file))
        assert cfg.high_risk_tcp_ports == [22, 23]
        assert cfg.high_risk_udp_ports == [53]

    def test_toml_overrides_defaults(self, tmp_path):
        """TOML 文件覆盖默认值。"""
        toml_file = tmp_path / "custom.toml"
        toml_file.write_text(
            '[overwide]\ncritical_ports = [1234]\n',
            encoding="utf-8",
        )
        cfg = load_config(str(toml_file))
        assert cfg.overwide.critical_ports == [1234]
        # 未设置的字段保持默认
        assert cfg.high_risk_tcp_ports == DEFAULT_HIGH_RISK_TCP_PORTS

    def test_invalid_toml_falls_to_default(self, tmp_path, monkeypatch):
        """无效 TOML 文件静默降级为默认值。"""
        monkeypatch.chdir(tmp_path)
        bad_file = tmp_path / "bad.toml"
        bad_file.write_text("this is not valid [[[[ toml", encoding="utf-8")
        cfg = load_config(str(bad_file))
        assert isinstance(cfg, AnalyzerConfig)

    def test_nonexistent_path_falls_to_default(self, tmp_path, monkeypatch):
        """不存在路径降级为默认值。"""
        monkeypatch.chdir(tmp_path)
        cfg = load_config("/tmp/does_not_exist_fw_analyzer.toml")
        assert isinstance(cfg, AnalyzerConfig)

    def test_cwd_fallback(self, tmp_path, monkeypatch):
        """当前目录 fw-analyzer.toml 作为 fallback。"""
        monkeypatch.chdir(tmp_path)
        toml_file = tmp_path / "fw-analyzer.toml"
        toml_file.write_text(
            '[high_risk_ports]\ntcp = [9999]\n',
            encoding="utf-8",
        )
        cfg = load_config()  # 无显式路径
        assert cfg.high_risk_tcp_ports == [9999]

    def test_partial_config(self, tmp_path):
        """部分配置：只设置 compliance。"""
        toml_file = tmp_path / "partial.toml"
        toml_file.write_text(
            '[compliance]\ncheck_cleartext = false\n',
            encoding="utf-8",
        )
        cfg = load_config(str(toml_file))
        assert cfg.compliance.check_cleartext is False
        # 其他开关保持默认
        assert cfg.compliance.check_permit_any_any is True

    def test_compliance_cleartext_ports(self, tmp_path):
        """设置 compliance 的明文端口列表。"""
        toml_file = tmp_path / "comp.toml"
        toml_file.write_text(
            '[compliance]\ncleartext_ports = [21, 23]\n',
            encoding="utf-8",
        )
        cfg = load_config(str(toml_file))
        assert cfg.compliance.cleartext_ports == [21, 23]
