"""
fw_analyzer/parsers/palo_alto.py

Palo Alto PAN-OS 配置解析器（XML 格式）。

支持以下配置结构：
  <address>           → 地址对象（ip-netmask / ip-range / fqdn）
  <address-group>     → 地址组（静态成员 / 动态成员，仅处理静态）
  <service>           → 服务对象（tcp/udp + 端口范围）
  <service-group>     → 服务组
  <security>
    <rules>
      <entry name="...">  → 安全策略规则

注意：
  - 使用 xml.etree.ElementTree，不引入第三方 XML 库
  - 规则中 application 字段忽略（仅提取网络层 5 元组）
  - 内置服务名（application-default 等）作为 "any" 处理
  - disabled 规则：<disabled>yes</disabled> → enabled=False
  - negate-source / negate-destination 不处理（保留 PARSE_WARN）
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Literal

from .base import AbstractParser
from ..models.rule import FlatRule, Warning, WarningSeverity, ParseResult
from ..models.port_range import PortRange
from ..models.object_store import AddressObject, ServiceObject
from ..models.ip_utils import parse_ipv4_network, NonContiguousWildcardError


# PAN-OS 内置服务名称映射（常见预定义服务）
PANOS_BUILTIN_SERVICES: dict[str, list[tuple[str, int, int]]] = {
    "service-http":   [("tcp", 80, 80)],
    "service-https":  [("tcp", 443, 443)],
    "ssh":            [("tcp", 22, 22)],
    "telnet":         [("tcp", 23, 23)],
    "ftp":            [("tcp", 21, 21)],
    "smtp":           [("tcp", 25, 25)],
    "dns":            [("udp", 53, 53)],
    "snmp":           [("udp", 161, 161)],
    "rdp":            [("tcp", 3389, 3389)],
    "mysql":          [("tcp", 3306, 3306)],
    "mssql":          [("tcp", 1433, 1433)],
    "ping":           [("icmp", 0, 0)],
    "icmp":           [("icmp", 0, 0)],
    "ntp":            [("udp", 123, 123)],
    "syslog":         [("udp", 514, 514)],
    "ldap":           [("tcp", 389, 389)],
    "ldaps":          [("tcp", 636, 636)],
    "kerberos":       [("tcp", 88, 88), ("udp", 88, 88)],
}


# PAN-OS application → 默认协议/端口映射
# 当 service=application-default 且 application 不为 any 时使用
# 格式: { app_name: [(protocol, dst_port_lo, dst_port_hi), ...] }
PANOS_APP_TO_PROTOCOL: dict[str, list[tuple[str, int, int]]] = {
    # ICMP 相关
    "icmp":           [("icmp", 0, 0)],
    "ping":           [("icmp", 0, 0)],
    "traceroute":     [("icmp", 0, 0)],
    "ping6":          [("icmp", 0, 0)],
    "ping-tunnel":    [("icmp", 0, 0)],
    # DNS
    "dns":            [("udp", 53, 53), ("tcp", 53, 53)],
    # Web
    "web-browsing":   [("tcp", 80, 80)],
    "ssl":            [("tcp", 443, 443)],
    # SSH / Telnet
    "ssh":            [("tcp", 22, 22)],
    "telnet":         [("tcp", 23, 23)],
    # FTP
    "ftp":            [("tcp", 21, 21)],
    # SMTP / Email
    "smtp":           [("tcp", 25, 25)],
    "pop3":           [("tcp", 110, 110)],
    "imap":           [("tcp", 143, 143)],
    # NTP
    "ntp":            [("udp", 123, 123)],
    # SNMP
    "snmp":           [("udp", 161, 161)],
    # LDAP
    "ldap":           [("tcp", 389, 389)],
    # Syslog
    "syslog":         [("udp", 514, 514)],
    # RDP
    "ms-rdp":         [("tcp", 3389, 3389)],
    # Database
    "mysql":          [("tcp", 3306, 3306)],
    "mssql-db":       [("tcp", 1433, 1433)],
    "oracle-database": [("tcp", 1521, 1521)],
    "postgresql":     [("tcp", 5432, 5432)],
    # DHCP
    "dhcp":           [("udp", 67, 68)],
    # Kerberos
    "kerberos":       [("tcp", 88, 88), ("udp", 88, 88)],
    # SMB
    "ms-ds-smb":      [("tcp", 445, 445)],
    # RADIUS
    "radius":         [("udp", 1812, 1812)],
    # TFTP
    "tftp":           [("udp", 69, 69)],
    # NetBIOS
    "netbios-dg":     [("udp", 138, 138)],
    "netbios-ns":     [("udp", 137, 137)],
    "netbios-ss":     [("tcp", 139, 139)],
    # Microsoft Outlook
    "ms-outlook-downloading":     [("tcp", 443, 443)],
    "ms-outlook-personal-uploading": [("tcp", 443, 443)],
    "ms-outlook-uploading":       [("tcp", 443, 443)],
    "outlook-web":                [("tcp", 443, 443)],
    "outlook-web-online":         [("tcp", 443, 443)],
}


class PaloAltoParser(AbstractParser):
    """Palo Alto PAN-OS XML 配置解析器。"""

    @property
    def vendor(self) -> str:
        return "paloalto"

    # ------------------------------------------------------------------
    # 阶段1：解析对象定义
    # ------------------------------------------------------------------

    def _parse_objects(self, text: str) -> None:
        """解析 PAN-OS XML 配置中的所有对象定义。"""
        try:
            root = ET.fromstring(text)
        except ET.ParseError as e:
            self._warn(f"XML 解析失败: {e}", code="PARSE_WARN", severity=WarningSeverity.ERROR)
            return

        # 寻找 vsys 或 shared 节点（支持多种层级结构）
        # 常见结构：<config><devices><entry><vsys><entry name="vsys1">...
        #           <config><shared>...
        for addr_elem in root.iter("address"):
            self._parse_address_objects(addr_elem)

        for addrgrp_elem in root.iter("address-group"):
            self._parse_address_groups(addrgrp_elem)

        for svc_elem in root.iter("service"):
            # 避免重复处理规则内的 <service> 子元素
            # service 对象的 entry 下有 <protocol> 子节点
            for entry in svc_elem.findall("entry"):
                if entry.find("protocol") is not None:
                    self._parse_service_entry(entry)

        for svcgrp_elem in root.iter("service-group"):
            self._parse_service_groups(svcgrp_elem)

        # 注册内置服务
        for name, ports in PANOS_BUILTIN_SERVICES.items():
            if not self.object_store.has_service(name):
                for proto, lo, hi in ports:
                    self.object_store.add_service_object(
                        name, proto,
                        dst_port=PortRange(lo, hi),
                    )

    def _parse_address_objects(self, addr_elem: ET.Element) -> None:
        """解析 <address> 节点下的所有 <entry>。"""
        for entry in addr_elem.findall("entry"):
            name = entry.get("name", "")
            if not name:
                continue

            ip_netmask = entry.findtext("ip-netmask")
            ip_range = entry.findtext("ip-range")
            fqdn = entry.findtext("fqdn")

            if ip_netmask:
                # ip-netmask: "10.0.0.0/24" 或 "10.0.0.1" （单IP）
                ip_netmask = ip_netmask.strip()
                try:
                    self.object_store.add_address_object(name, "subnet", ip_netmask)
                except Exception:
                    self.object_store.add_address_object(name, "unknown", ip_netmask)
            elif ip_range:
                # ip-range: "10.0.0.1-10.0.0.10"
                self.object_store.add_address_object(name, "range", ip_range.strip())
            elif fqdn:
                self.object_store.add_address_object(name, "fqdn", fqdn.strip())
            else:
                self.object_store.add_address_object(name, "unknown", name)

    def _parse_address_groups(self, addrgrp_elem: ET.Element) -> None:
        """解析 <address-group> 节点下的所有 <entry>。"""
        for entry in addrgrp_elem.findall("entry"):
            name = entry.get("name", "")
            if not name:
                continue

            static_elem = entry.find("static")
            if static_elem is not None:
                members = [m.text.strip() for m in static_elem.findall("member") if m.text]
                self.object_store.add_address_group(name, members)
            else:
                # dynamic 地址组（基于 tag），无法静态展开
                self._warn(
                    f"地址组 '{name}' 为动态地址组（基于 tag），无法静态展开，已跳过。",
                    code="PARSE_WARN",
                    severity=WarningSeverity.INFO,
                )
                # 注册为空组，防止 UNRESOLVED_OBJECT 警告
                self.object_store.add_address_group(name, [])

    def _parse_service_entry(self, entry: ET.Element) -> None:
        """解析单个服务 <entry>。"""
        name = entry.get("name", "")
        if not name:
            return

        protocol_elem = entry.find("protocol")
        if protocol_elem is None:
            return

        # TCP
        tcp_elem = protocol_elem.find("tcp")
        if tcp_elem is not None:
            port_text = tcp_elem.findtext("port") or "any"
            src_port_text = tcp_elem.findtext("source-port") or "any"
            dst_pr = self._parse_panos_port(port_text)
            src_pr = self._parse_panos_port(src_port_text)
            self.object_store.add_service_object(name, "tcp", dst_port=dst_pr, src_port=src_pr)
            return

        # UDP
        udp_elem = protocol_elem.find("udp")
        if udp_elem is not None:
            port_text = udp_elem.findtext("port") or "any"
            src_port_text = udp_elem.findtext("source-port") or "any"
            dst_pr = self._parse_panos_port(port_text)
            src_pr = self._parse_panos_port(src_port_text)
            self.object_store.add_service_object(name, "udp", dst_port=dst_pr, src_port=src_pr)
            return

        # SCTP
        sctp_elem = protocol_elem.find("sctp")
        if sctp_elem is not None:
            port_text = sctp_elem.findtext("port") or "any"
            dst_pr = self._parse_panos_port(port_text)
            self.object_store.add_service_object(name, "sctp", dst_port=dst_pr)
            return

    def _parse_panos_port(self, port_text: str) -> PortRange:
        """
        解析 PAN-OS 端口字符串。

        格式：
          "any"           → PortRange.any()
          "80"            → PortRange(80, 80)
          "80-443"        → PortRange(80, 443)
          "80,443,8080"   → 仅取第一段（TODO：PortRange 目前不支持多段，记录警告）
          "80-443,8080"   → 仅取第一段
        """
        port_text = port_text.strip()
        if not port_text or port_text.lower() == "any":
            return PortRange.any()

        # 取第一段（逗号分隔）
        first = port_text.split(",")[0].strip()

        m = re.match(r"^(\d+)(?:-(\d+))?$", first)
        if m:
            lo = int(m.group(1))
            hi = int(m.group(2)) if m.group(2) else lo
            return PortRange(lo, hi)

        return PortRange.any()

    def _parse_service_groups(self, svcgrp_elem: ET.Element) -> None:
        """解析 <service-group> 节点下的所有 <entry>。"""
        for entry in svcgrp_elem.findall("entry"):
            name = entry.get("name", "")
            if not name:
                continue
            members_elem = entry.find("members")
            if members_elem is not None:
                members = [m.text.strip() for m in members_elem.findall("member") if m.text]
                self.object_store.add_service_group(name, members)
            else:
                self.object_store.add_service_group(name, [])

    # ------------------------------------------------------------------
    # 阶段2：解析安全策略规则
    # ------------------------------------------------------------------

    def _parse_rules(self, text: str) -> list[FlatRule]:
        """解析 PAN-OS XML 中的安全策略规则。"""
        try:
            root = ET.fromstring(text)
        except ET.ParseError:
            return []

        rules: list[FlatRule] = []
        seq = 0

        # 找所有 security/rules/entry
        for rules_elem in root.iter("rules"):
            # 只处理在 security 节点下的 rules
            for entry in rules_elem.findall("entry"):
                rule = self._parse_rule_entry(entry, seq)
                if rule:
                    rules.append(rule)
                    seq += 1

        return rules

    def _parse_rule_entry(self, entry: ET.Element, seq: int) -> FlatRule | None:
        """解析单条安全策略规则 <entry>。"""
        name = entry.get("name", f"rule-{seq}")
        rule_warnings: list[Warning] = []

        # --- 启用/禁用 ---
        disabled_text = entry.findtext("disabled") or "no"
        enabled = disabled_text.strip().lower() != "yes"

        # --- 动作 ---
        action_text = (entry.findtext("action") or "deny").strip().lower()
        if action_text == "allow":
            action: Literal["permit", "deny", "drop", "reject"] = "permit"
        elif action_text in ("deny", "drop", "reset-client", "reset-server", "reset-both"):
            action = "drop"
        else:
            action = "deny"

        # --- 源/目的 Zone ---
        src_zone = self._collect_members(entry, "from")
        dst_zone = self._collect_members(entry, "to")

        # --- 源地址 ---
        src_negate = (entry.findtext("negate-source") or "no").strip().lower() == "yes"
        if src_negate:
            rule_warnings.append(Warning(
                code="PARSE_WARN",
                message=f"规则 '{name}' 使用了 negate-source，取反语义未处理，地址保留原值。",
                severity=WarningSeverity.WARN,
            ))
        src_member_names = self._get_member_names(entry, "source")

        # --- 目的地址 ---
        dst_negate = (entry.findtext("negate-destination") or "no").strip().lower() == "yes"
        if dst_negate:
            rule_warnings.append(Warning(
                code="PARSE_WARN",
                message=f"规则 '{name}' 使用了 negate-destination，取反语义未处理，地址保留原值。",
                severity=WarningSeverity.WARN,
            ))
        dst_member_names = self._get_member_names(entry, "destination")

        # --- 服务 ---
        svc_member_names = self._get_member_names(entry, "service")

        # --- 应用 ---
        app_member_names = self._get_member_names(entry, "application")

        # --- 展开地址 ---
        src_ip = self._resolve_address_list(src_member_names)
        dst_ip = self._resolve_address_list(dst_member_names)

        # --- 展开服务 ---
        # application-default / any 特殊处理
        services = self._resolve_service_list(svc_member_names, app_member_names)

        # --- 描述/注释 ---
        comment = entry.findtext("description") or ""

        # 转移 object_store 警告到规则
        for sw in self.object_store.warnings:
            rule_warnings.append(Warning.from_store_warning(sw))
        self.object_store.warnings.clear()

        return FlatRule(
            vendor=self.vendor,
            raw_rule_id=name,
            rule_name=name,
            seq=seq,
            src_ip=src_ip,
            dst_ip=dst_ip,
            services=services,
            action=action,
            src_zone="; ".join(src_zone),
            dst_zone="; ".join(dst_zone),
            enabled=enabled,
            comment=comment,
            warnings=rule_warnings,
        )

    # ------------------------------------------------------------------
    # 辅助方法
    # ------------------------------------------------------------------

    def _collect_members(self, elem: ET.Element, tag: str) -> list[str]:
        """收集 <tag><member>xxx</member>... 中的所有成员文本。"""
        container = elem.find(tag)
        if container is None:
            return []
        return [m.text.strip() for m in container.findall("member") if m.text]

    def _get_member_names(self, entry: ET.Element, tag: str) -> list[str]:
        """
        获取规则中某个字段的成员名称列表。
        空列表或仅含 "any" 时返回 ["any"]。
        """
        members = self._collect_members(entry, tag)
        if not members:
            return ["any"]
        return members

    def _resolve_address_list(self, names: list[str]) -> list[AddressObject]:
        """展开地址名称列表，合并所有结果并去重。"""
        if names == ["any"]:
            from ..models.ip_utils import parse_ipv4_network
            return [AddressObject(
                name="any", type="any", value="0.0.0.0/0",
                network=parse_ipv4_network("0.0.0.0/0"),
            )]
        result: list[AddressObject] = []
        seen: set[str] = set()
        for name in names:
            for obj in self.object_store.resolve_address(name):
                if obj.value not in seen:
                    seen.add(obj.value)
                    result.append(obj)
        return result

    def _resolve_service_list(
        self, names: list[str], app_names: list[str] | None = None,
    ) -> list[ServiceObject]:
        """
        展开服务名称列表。

        当 service 为 application-default 且 application 不为 any 时，
        根据 PANOS_APP_TO_PROTOCOL 映射生成对应的 ServiceObject。
        其余情况：application-default / any → 空列表（any）。
        """
        result: list[ServiceObject] = []
        seen: set[str] = set()

        for name in names:
            if name.lower() == "any":
                return []
            if name.lower() == "application-default":
                return self._resolve_app_default_services(app_names or [])
            for obj in self.object_store.resolve_service(name):
                key = str(obj)
                if key not in seen:
                    seen.add(key)
                    result.append(obj)
        return result

    @staticmethod
    def _resolve_app_default_services(
        app_names: list[str],
    ) -> list[ServiceObject]:
        """
        当 service=application-default 时，根据 application 列表推断协议/端口。

        如果所有 application 都能映射，返回合并后的 ServiceObject 列表。
        如果 application 为 any 或有任何未知应用，返回空列表（等同于 any）。
        """
        if not app_names or any(a.lower() == "any" for a in app_names):
            return []

        result: list[ServiceObject] = []
        seen: set[str] = set()

        for app in app_names:
            mapping = PANOS_APP_TO_PROTOCOL.get(app.lower())
            if mapping is None:
                # 未知应用，无法推断协议，回退到 any
                return []
            for proto, lo, hi in mapping:
                svc = ServiceObject(
                    name=f"app:{app}",
                    protocol=proto,
                    src_port=PortRange.any(),
                    dst_port=PortRange(lo, hi),
                )
                key = str(svc)
                if key not in seen:
                    seen.add(key)
                    result.append(svc)

        return result

    # AbstractParser 的两阶段接口由基类 parse() 统一调度，此处无需覆盖。
