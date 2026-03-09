"""
fw_analyzer/config.py

分析器配置：高危端口、合规检查开关等。

配置文件格式（TOML）：
  [high_risk_ports]
  tcp = [21, 23, 110, 143, 1433, 3306, 3389]
  udp = [161, 162]

  [overwide]
  # 过宽规则检测的端口分级（CRITICAL/HIGH/MEDIUM/LOW）
  critical_ports = [22, 23, 3389]

  [compliance]
  check_permit_any_any = true
  check_no_implicit_deny = true
  check_cleartext = true
  check_high_risk_ports = true
  check_no_comment = true
  check_disabled_rules = true

加载优先级（高到低）：
  1. CLI --config 参数指定路径
  2. 当前目录 ./fw-analyzer.toml
  3. 用户主目录 ~/.fw-analyzer/config.toml
  4. 内置默认值
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ------------------------------------------------------------------
# 内置默认高危端口
# ------------------------------------------------------------------

DEFAULT_HIGH_RISK_TCP_PORTS: list[int] = [
    20, 21,     # FTP
    23,         # Telnet
    25,         # SMTP
    53,         # DNS（TCP）
    110,        # POP3
    139,        # NetBIOS Session（SMB/CIFS）
    143,        # IMAP
    389,        # LDAP
    445,        # SMB/CIFS（直接 TCP）
    512, 513, 514,  # rsh/rexec/rlogin
    1433,       # MSSQL
    1521,       # Oracle
    3306,       # MySQL
    3389,       # RDP
    4444,       # Metasploit 默认监听
    5432,       # PostgreSQL
    5900,       # VNC
    6379,       # Redis
    10022,      # 自定义 SSH
    27017,      # MongoDB
]

DEFAULT_HIGH_RISK_UDP_PORTS: list[int] = [
    53,         # DNS
    69,         # TFTP
    137, 138,   # NetBIOS Name/Datagram（CIFS 相关）
    161, 162,   # SNMP/Trap
    514,        # Syslog
]

# 过宽规则分级端口
DEFAULT_OVERWIDE_CRITICAL_PORTS: list[int] = [22, 23, 139, 445, 3389, 4444, 10022]
DEFAULT_OVERWIDE_HIGH_PORTS: list[int] = [21, 25, 1433, 3306, 5432, 6379, 27017]
DEFAULT_OVERWIDE_MEDIUM_PORTS: list[int] = [110, 143, 161, 162, 389, 512, 513, 514]
DEFAULT_OVERWIDE_LOW_PORTS: list[int] = [20, 53, 69, 1521, 5900]


# ------------------------------------------------------------------
# 合规检查配置
# ------------------------------------------------------------------

@dataclass
class ComplianceConfig:
    """合规检查开关。"""
    check_permit_any_any: bool = True
    check_no_implicit_deny: bool = True
    check_cleartext: bool = True
    check_high_risk_ports: bool = True
    check_no_comment: bool = True
    check_disabled_rules: bool = True

    # 明文协议高危端口（用于 CLEARTEXT 检测）
    cleartext_ports: list[int] = field(default_factory=lambda: [21, 23, 25, 80, 110, 143, 161, 389, 514])


# ------------------------------------------------------------------
# 过宽检测配置
# ------------------------------------------------------------------

@dataclass
class OverwideConfig:
    """过宽规则检测的端口分级。"""
    critical_ports: list[int] = field(default_factory=lambda: list(DEFAULT_OVERWIDE_CRITICAL_PORTS))
    high_ports: list[int] = field(default_factory=lambda: list(DEFAULT_OVERWIDE_HIGH_PORTS))
    medium_ports: list[int] = field(default_factory=lambda: list(DEFAULT_OVERWIDE_MEDIUM_PORTS))
    low_ports: list[int] = field(default_factory=lambda: list(DEFAULT_OVERWIDE_LOW_PORTS))

    def get_severity(self, port: int) -> str | None:
        """
        返回端口对应的严重等级字符串，如果不在列表中返回 None。

        返回值: "CRITICAL" / "HIGH" / "MEDIUM" / "LOW" / None
        """
        if port in self.critical_ports:
            return "CRITICAL"
        if port in self.high_ports:
            return "HIGH"
        if port in self.medium_ports:
            return "MEDIUM"
        if port in self.low_ports:
            return "LOW"
        return None


# ------------------------------------------------------------------
# 主配置类
# ------------------------------------------------------------------

@dataclass
class AnalyzerConfig:
    """
    分析器全局配置。

    包含高危端口列表、过宽分级、合规检查开关等。
    """
    high_risk_tcp_ports: list[int] = field(
        default_factory=lambda: list(DEFAULT_HIGH_RISK_TCP_PORTS)
    )
    high_risk_udp_ports: list[int] = field(
        default_factory=lambda: list(DEFAULT_HIGH_RISK_UDP_PORTS)
    )
    overwide: OverwideConfig = field(default_factory=OverwideConfig)
    compliance: ComplianceConfig = field(default_factory=ComplianceConfig)

    def is_high_risk(self, protocol: str, port: int) -> bool:
        """判断给定协议+端口是否属于高危端口。"""
        proto = protocol.lower()
        if proto in ("tcp", "tcp-udp"):
            if port in self.high_risk_tcp_ports:
                return True
        if proto in ("udp", "tcp-udp"):
            if port in self.high_risk_udp_ports:
                return True
        return False


# ------------------------------------------------------------------
# 配置加载函数
# ------------------------------------------------------------------

def _load_toml(path: Path) -> dict:
    """加载 TOML 文件，返回 dict。Python 3.11+ 使用内置 tomllib，旧版用 tomli。"""
    if sys.version_info >= (3, 11):
        import tomllib  # type: ignore[import]
        with open(path, "rb") as f:
            return tomllib.load(f)
    else:
        try:
            import tomli  # type: ignore[import]
            with open(path, "rb") as f:
                return tomli.load(f)
        except ImportError:
            # 如果没有安装 tomli，尝试手动解析基础 TOML（简单 key=value 和 [section]）
            return _simple_toml_parse(path)


def _simple_toml_parse(path: Path) -> dict:
    """
    极简 TOML 解析器，仅支持 [section] + key = value/[list] 语法。
    作为 tomli 不可用时的降级方案。
    """
    result: dict = {}
    current_section: dict = result
    current_key_path: list[str] = []

    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1].strip()
                parts = section.split(".")
                current_section = result
                current_key_path = []
                for part in parts:
                    current_key_path.append(part)
                    if part not in current_section:
                        current_section[part] = {}
                    current_section = current_section[part]
            elif "=" in line:
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip()
                # 解析列表
                if val.startswith("[") and val.endswith("]"):
                    inner = val[1:-1].strip()
                    if inner:
                        items = [v.strip() for v in inner.split(",")]
                        parsed = []
                        for item in items:
                            item = item.strip()
                            try:
                                parsed.append(int(item))
                            except ValueError:
                                parsed.append(item.strip('"\''))
                        current_section[key] = parsed
                    else:
                        current_section[key] = []
                elif val.lower() in ("true", "false"):
                    current_section[key] = val.lower() == "true"
                else:
                    try:
                        current_section[key] = int(val)
                    except ValueError:
                        current_section[key] = val.strip('"\'')

    return result


def load_config(config_path: Optional[str] = None) -> AnalyzerConfig:
    """
    加载分析器配置，按优先级查找配置文件。

    加载优先级（高到低）：
      1. config_path 参数（CLI --config）
      2. ./fw-analyzer.toml（当前工作目录）
      3. ~/.fw-analyzer/config.toml（用户主目录）
      4. 内置默认值

    Args:
        config_path: 可选的配置文件路径字符串

    Returns:
        AnalyzerConfig 实例
    """
    candidates: list[Path] = []

    if config_path:
        candidates.append(Path(config_path))

    candidates.append(Path.cwd() / "fw-analyzer.toml")
    candidates.append(Path.home() / ".fw-analyzer" / "config.toml")

    for path in candidates:
        if path.exists():
            try:
                data = _load_toml(path)
                return _build_config(data)
            except Exception:
                # 配置文件有误时降级使用默认值
                pass

    return AnalyzerConfig()


def _build_config(data: dict) -> AnalyzerConfig:
    """从 TOML dict 构建 AnalyzerConfig。"""
    cfg = AnalyzerConfig()

    # [high_risk_ports]
    hrp = data.get("high_risk_ports", {})
    if isinstance(hrp, dict):
        if "tcp" in hrp and isinstance(hrp["tcp"], list):
            cfg.high_risk_tcp_ports = [int(p) for p in hrp["tcp"]]
        if "udp" in hrp and isinstance(hrp["udp"], list):
            cfg.high_risk_udp_ports = [int(p) for p in hrp["udp"]]

    # [overwide]
    ow = data.get("overwide", {})
    if isinstance(ow, dict):
        if "critical_ports" in ow:
            cfg.overwide.critical_ports = [int(p) for p in ow["critical_ports"]]
        if "high_ports" in ow:
            cfg.overwide.high_ports = [int(p) for p in ow["high_ports"]]
        if "medium_ports" in ow:
            cfg.overwide.medium_ports = [int(p) for p in ow["medium_ports"]]
        if "low_ports" in ow:
            cfg.overwide.low_ports = [int(p) for p in ow["low_ports"]]

    # [compliance]
    comp = data.get("compliance", {})
    if isinstance(comp, dict):
        for attr in (
            "check_permit_any_any",
            "check_no_implicit_deny",
            "check_cleartext",
            "check_high_risk_ports",
            "check_no_comment",
            "check_disabled_rules",
        ):
            if attr in comp and isinstance(comp[attr], bool):
                setattr(cfg.compliance, attr, comp[attr])
        if "cleartext_ports" in comp and isinstance(comp["cleartext_ports"], list):
            cfg.compliance.cleartext_ports = [int(p) for p in comp["cleartext_ports"]]

    return cfg
