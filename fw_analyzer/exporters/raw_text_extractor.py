"""
fw_analyzer/exporters/raw_text_extractor.py

从原始配置文本中按对象名称提取对象定义块。

各厂商的对象定义格式不同，此工具类提供统一接口：
  extract(vendor, config_text, object_names) -> dict[str, str]

返回 {对象名: 定义文本} 映射，找不到的对象名不包含在返回结果中。
"""
from __future__ import annotations

import re


class RawTextExtractor:
    """从原始防火墙配置文本中提取对象定义。"""

    def extract(
        self, vendor: str, config_text: str, object_names: list[str],
    ) -> dict[str, str]:
        """根据厂商调度对应的提取方法。

        Args:
            vendor: 厂商标识（"cisco-asa" / "huawei" / "paloalto" / "fortinet"）
            config_text: 完整的原始配置文本
            object_names: 需要提取定义的对象名列表

        Returns:
            {对象名: 定义原文} 字典
        """
        if not object_names or not config_text:
            return {}

        dispatch = {
            "cisco-asa": self._extract_cisco,
            "huawei": self._extract_huawei,
            "paloalto": self._extract_paloalto,
            "fortinet": self._extract_fortinet,
        }
        func = dispatch.get(vendor)
        if not func:
            return {}
        return func(config_text, object_names)

    # ------------------------------------------------------------------
    # Cisco ASA
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_cisco(text: str, names: list[str]) -> dict[str, str]:
        """提取 Cisco ASA object / object-group 定义块。

        格式示例：
          object-group network ITO-40203-SRC
           network-object host 10.1.2.3
           network-object 192.168.1.0 255.255.255.0
          object network web-server
           host 10.0.0.1
        """
        result: dict[str, str] = {}
        for name in names:
            escaped = re.escape(name)
            pattern = re.compile(
                rf"^(object(?:-group)?\s+(?:network|service)\s+{escaped}(?:\s+\S+)?\s*\n"
                rf"(?:[ \t]+.+\n?)*)",
                re.MULTILINE,
            )
            m = pattern.search(text)
            if m:
                result[name] = m.group(1).rstrip()
        return result

    # ------------------------------------------------------------------
    # Huawei USG
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_huawei(text: str, names: list[str]) -> dict[str, str]:
        """提取华为 USG 对象定义块。

        格式示例：
          ip address-set ADDR_SET type group
            address 0 address-set SUB_SET
          ip service-set SVC_SET type object
            service 0 protocol tcp destination-port 80
        """
        result: dict[str, str] = {}
        for name in names:
            escaped = re.escape(name)
            # 支持引号名称和非引号名称
            name_pat = rf'(?:"{escaped}"|{escaped})'
            # ip address-set / ip service-set / ip address-group
            pattern = re.compile(
                rf'^(ip\s+(?:address-set|service-set|address-group|service-group)'
                rf'\s+{name_pat}(?:\s+type\s+\w+)?.*?)(?=^ip\s+(?:address|service)|^#|\Z)',
                re.MULTILINE | re.DOTALL,
            )
            m = pattern.search(text)
            if m:
                result[name] = m.group(1).rstrip()
        return result

    # ------------------------------------------------------------------
    # Palo Alto PAN-OS (set format)
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_paloalto(text: str, names: list[str]) -> dict[str, str]:
        """提取 PAN-OS set 格式的对象定义行。

        格式示例：
          set address web-server ip-netmask 10.0.0.1/32
          set address-group DMZ-Servers static web-server
          set service HTTPS protocol tcp port 443
        """
        result: dict[str, str] = {}
        lines = text.splitlines()
        for name in names:
            escaped = re.escape(name)
            # 匹配 address / service / address-group / service-group 定义
            pattern = re.compile(
                rf'^set\s+(?:address|service|address-group|service-group)'
                rf'\s+(?:"{escaped}"|{escaped})\s+',
            )
            matched_lines = [ln for ln in lines if pattern.match(ln.strip())]
            if matched_lines:
                result[name] = "\n".join(matched_lines)
        return result

    # ------------------------------------------------------------------
    # Fortinet FortiGate
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_fortinet(text: str, names: list[str]) -> dict[str, str]:
        """提取 FortiGate 对象定义块。

        从 config firewall address / addrgrp / service custom / service group
        段中提取 edit "<name>" ... next 块。
        """
        result: dict[str, str] = {}
        # 定位所有 config firewall (address|addrgrp|service custom|service group) 段
        section_re = re.compile(
            r'^config\s+firewall\s+'
            r'(?:address|addrgrp|service\s+custom|service\s+group)\s*$'
            r'(.*?)^end\s*$',
            re.MULTILINE | re.DOTALL,
        )
        sections = section_re.findall(text)
        for name in names:
            escaped = re.escape(name)
            # edit "name" ... next (or edit name ... next)
            # Stop at 'next' line (end of edit block) — include 'next' in match
            edit_re = re.compile(
                rf'(^\s*edit\s+(?:"{escaped}"|{escaped})\s*$'
                rf'.*?'
                rf'^\s*next\s*$)',
                re.MULTILINE | re.DOTALL,
            )
            for section in sections:
                m = edit_re.search(section)
                if m:
                    result[name] = m.group(1).strip()
                    break
        return result
