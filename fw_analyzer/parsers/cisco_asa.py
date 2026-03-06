"""
fw_analyzer/parsers/cisco_asa.py

Cisco ASA 防火墙配置解析器。

支持特性：
  - object network / object service（单对象定义）
  - object-group network（含 group-object 嵌套，递归展开）
  - object-group service（含 port-object / service-object / group-object）
  - access-list <name> extended permit|deny ...
  - 引用方式：object <name> 和 object-group <name> 两种

注意：
  - object 和 object-group 是两种不同的引用路径，不能混淆
  - Cisco ASA 的掩码使用 subnet mask（非 wildcard）
  - access-list 行内可混合使用直接 IP、object 引用、object-group 引用
"""
from __future__ import annotations

import re
from typing import Literal

from .base import AbstractParser
from ..models.rule import FlatRule
from ..models.port_range import PortRange
from ..models.object_store import AddressObject, ServiceObject


# Cisco ASA 内置服务/协议映射
ASA_BUILTIN_SERVICES: dict[str, tuple[str, int, int]] = {
    "http":         ("tcp", 80, 80),
    "https":        ("tcp", 443, 443),
    "ftp":          ("tcp", 21, 21),
    "ftp-data":     ("tcp", 20, 20),
    "ssh":          ("tcp", 22, 22),
    "telnet":       ("tcp", 23, 23),
    "smtp":         ("tcp", 25, 25),
    "domain":       ("udp", 53, 53),
    "snmp":         ("udp", 161, 161),
    "syslog":       ("udp", 514, 514),
    "tftp":         ("udp", 69, 69),
    "ntp":          ("udp", 123, 123),
    "bgp":          ("tcp", 179, 179),
    "ldap":         ("tcp", 389, 389),
    "ms-sql-s":     ("tcp", 1433, 1433),
    "oracle":       ("tcp", 1521, 1521),
    "radius":       ("udp", 1812, 1812),
    "rdp":          ("tcp", 3389, 3389),
    "echo":         ("icmp", 8, 8),
    "unreachable":  ("icmp", 3, 3),
}

# Cisco ASA 端口名称映射
ASA_PORT_NAMES: dict[str, int] = {
    "ftp":       21, "ssh": 22, "telnet": 23, "smtp": 25,
    "domain":    53, "http": 80, "https": 443, "pop3": 110,
    "nntp":     119, "ntp": 123, "imap": 143, "snmp": 161,
    "bgp":      179, "ldap": 389, "netbios-ssn": 139,
    "ms-sql-s": 1433, "oracle": 1521, "radius": 1812,
    "rdp":      3389,
}


class CiscoAsaParser(AbstractParser):
    """Cisco ASA 防火墙配置解析器。"""

    @property
    def vendor(self) -> str:
        return "cisco-asa"

    # ------------------------------------------------------------------
    # 阶段1：解析对象定义
    # ------------------------------------------------------------------

    def _parse_objects(self, text: str) -> None:
        """解析所有 object 和 object-group 定义。"""
        self._parse_object_network(text)
        self._parse_object_service(text)
        self._parse_object_group_network(text)
        self._parse_object_group_service(text)
        # 注册内置服务
        for name, (proto, lo, hi) in ASA_BUILTIN_SERVICES.items():
            if not self.object_store.has_service(name):
                self.object_store.add_service_object(name, proto, dst_port=PortRange(lo, hi))

    def _parse_object_network(self, text: str) -> None:
        """
        解析 object network 块（单个地址对象）。

        格式：
          object network <name>
            host <ip>
            subnet <ip> <mask>
            range <ip_start> <ip_end>
            fqdn <domain>
        """
        pattern = re.compile(
            r"^object\s+network\s+(\S+)\s*\n((?:[ \t]+.*\n?)*)",
            re.MULTILINE,
        )
        for m in pattern.finditer(text):
            name = m.group(1)
            block = m.group(2)

            host_m = re.search(r"host\s+(\d+\.\d+\.\d+\.\d+)", block)
            subnet_m = re.search(
                r"subnet\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)", block
            )
            range_m = re.search(
                r"range\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)", block
            )
            fqdn_m = re.search(r"fqdn\s+(?:v4\s+)?(\S+)", block)

            if host_m:
                self.object_store.add_address_object(name, "host", host_m.group(1))
            elif subnet_m:
                self.object_store.add_address_object(
                    name, "subnet", subnet_m.group(1), subnet_m.group(2)
                )
            elif range_m:
                val = f"{range_m.group(1)}-{range_m.group(2)}"
                self.object_store.add_address_object(name, "range", val)
            elif fqdn_m:
                self.object_store.add_address_object(name, "fqdn", fqdn_m.group(1))

    def _parse_object_service(self, text: str) -> None:
        """
        解析 object service 块。

        格式：
          object service <name>
            service (tcp|udp|icmp) [source <op> <port>] [destination <op> <port>]
        """
        pattern = re.compile(
            r"^object\s+service\s+(\S+)\s*\n((?:[ \t]+.*\n?)*)",
            re.MULTILINE,
        )
        for m in pattern.finditer(text):
            name = m.group(1)
            block = m.group(2)
            svc_m = re.search(
                r"service\s+(\w+)"
                r"(?:\s+source\s+(?:eq\s+(\S+)|range\s+(\S+)\s+(\S+)))?"
                r"(?:\s+destination\s+(?:eq\s+(\S+)|range\s+(\S+)\s+(\S+)))?",
                block,
            )
            if svc_m:
                proto = svc_m.group(1).lower()
                src_port = self._parse_asa_port_op(
                    svc_m.group(2), svc_m.group(3), svc_m.group(4)
                )
                dst_port = self._parse_asa_port_op(
                    svc_m.group(5), svc_m.group(6), svc_m.group(7)
                )
                self.object_store.add_service_object(name, proto, dst_port=dst_port, src_port=src_port)

    def _parse_object_group_network(self, text: str) -> None:
        """
        解析 object-group network 块（支持 group-object 嵌套引用）。

        格式：
          object-group network <name>
            network-object host <ip>
            network-object <ip> <mask>
            network-object object <obj-name>
            group-object <group-name>
            description <text>
        """
        pattern = re.compile(
            r"^object-group\s+network\s+(\S+)\s*\n((?:[ \t]+.*\n?)*)",
            re.MULTILINE,
        )
        for m in pattern.finditer(text):
            group_name = m.group(1)
            block = m.group(2)
            members: list[str] = []

            for line in block.splitlines():
                line = line.strip()
                if not line or line.startswith("description"):
                    continue

                # group-object（嵌套组引用）
                go_m = re.match(r"group-object\s+(\S+)", line)
                if go_m:
                    members.append(go_m.group(1))
                    continue

                # network-object object <name>（引用单对象）
                noo_m = re.match(r"network-object\s+object\s+(\S+)", line)
                if noo_m:
                    members.append(noo_m.group(1))
                    continue

                # network-object host <ip>
                host_m = re.match(r"network-object\s+host\s+(\d+\.\d+\.\d+\.\d+)", line)
                if host_m:
                    obj_name = f"{group_name}_{host_m.group(1)}_host"
                    self.object_store.add_address_object(obj_name, "host", host_m.group(1))
                    members.append(obj_name)
                    continue

                # network-object <ip> <mask>
                net_m = re.match(
                    r"network-object\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)", line
                )
                if net_m:
                    obj_name = f"{group_name}_{net_m.group(1)}_net"
                    self.object_store.add_address_object(
                        obj_name, "subnet", net_m.group(1), net_m.group(2)
                    )
                    members.append(obj_name)

            if members:
                self.object_store.add_address_group(group_name, members)

    def _parse_object_group_service(self, text: str) -> None:
        """
        解析 object-group service 块（支持 tcp/udp/tcp-udp 协议约束）。

        格式：
          object-group service <name> [tcp|udp|tcp-udp]
            port-object eq <port>
            port-object range <lo> <hi>
            service-object (tcp|udp|icmp|...) [destination eq/range ...]
            group-object <group-name>
        """
        pattern = re.compile(
            r"^object-group\s+service\s+(\S+)(?:\s+(tcp|udp|tcp-udp))?\s*\n((?:[ \t]+.*\n?)*)",
            re.MULTILINE,
        )
        for m in pattern.finditer(text):
            group_name = m.group(1)
            proto_hint = (m.group(2) or "tcp").lower()
            block = m.group(3)
            members: list[str] = []

            for line in block.splitlines():
                line = line.strip()
                if not line or line.startswith("description"):
                    continue

                # group-object（嵌套服务组引用）
                go_m = re.match(r"group-object\s+(\S+)", line)
                if go_m:
                    members.append(go_m.group(1))
                    continue

                # port-object eq <port>
                po_eq = re.match(r"port-object\s+eq\s+(\S+)", line)
                if po_eq:
                    port = self._resolve_port_name(po_eq.group(1))
                    svc_name = f"{group_name}_{proto_hint}_{port}"
                    self.object_store.add_service_object(
                        svc_name, proto_hint, dst_port=PortRange.single(port)
                    )
                    members.append(svc_name)
                    continue

                # port-object range <lo> <hi>
                po_range = re.match(r"port-object\s+range\s+(\S+)\s+(\S+)", line)
                if po_range:
                    lo = self._resolve_port_name(po_range.group(1))
                    hi = self._resolve_port_name(po_range.group(2))
                    svc_name = f"{group_name}_{proto_hint}_{lo}_{hi}"
                    self.object_store.add_service_object(
                        svc_name, proto_hint, dst_port=PortRange(lo, hi)
                    )
                    members.append(svc_name)
                    continue

                # service-object <proto> [destination eq/range ...]
                so_m = re.match(
                    r"service-object\s+(\w+)"
                    r"(?:\s+destination\s+(?:eq\s+(\S+)|range\s+(\S+)\s+(\S+)))?",
                    line,
                )
                if so_m:
                    proto = so_m.group(1).lower()
                    dst_port = self._parse_asa_port_op(
                        so_m.group(2), so_m.group(3), so_m.group(4)
                    )
                    svc_name = f"{group_name}_{proto}_{dst_port}"
                    self.object_store.add_service_object(svc_name, proto, dst_port=dst_port)
                    members.append(svc_name)

            if members:
                self.object_store.add_service_group(group_name, members)

    # ------------------------------------------------------------------
    # 阶段2：解析规则
    # ------------------------------------------------------------------

    def _parse_rules(self, text: str) -> list[FlatRule]:
        """
        解析 access-list extended 规则。

        格式（单行）：
          access-list <name> extended (permit|deny)
            (ip|tcp|udp|icmp|object-group <svc-grp>|object <svc-obj>)
            (any|host <ip>|<ip> <mask>|object <obj>|object-group <grp>) <- src
            (any|host <ip>|<ip> <mask>|object <obj>|object-group <grp>) <- dst
            [<port-spec>]
        """
        rules: list[FlatRule] = []
        # 按 ACL 名称分组，保持顺序
        acl_seqs: dict[str, int] = {}

        # 匹配 access-list 行（可能跨行，用行延续符）
        acl_pattern = re.compile(
            r"^access-list\s+(\S+)\s+extended\s+(permit|deny)\s+(.+)$",
            re.MULTILINE,
        )

        for m in acl_pattern.finditer(text):
            acl_name = m.group(1)
            action = self._normalize_action(m.group(2))
            rest = m.group(3).strip()

            # 检测并剥离尾部 log/log <level> 关键字
            log_match = re.search(r"\s+log(?:\s+\S+)?\s*$", rest)
            log_enabled = bool(log_match)
            if log_match:
                rest = rest[:log_match.start()]

            seq = acl_seqs.get(acl_name, 0)
            acl_seqs[acl_name] = seq + 1

            rule_id = f"{acl_name}-{seq}"

            # 解析服务部分（协议或 object-group service）
            services, rest = self._parse_acl_service(rest, rule_id)
            # 解析源地址
            src_addrs, rest = self._parse_acl_address_token(rest, rule_id, "src")
            # 解析目的地址
            dst_addrs, rest = self._parse_acl_address_token(rest, rule_id, "dst")
            # 解析目的端口（如果有）
            if rest.strip() and services:
                dst_port = self._parse_inline_port(rest.strip())
                if dst_port and not dst_port.is_any():
                    # 更新服务的目的端口
                    services = [
                        ServiceObject(
                            name=s.name, protocol=s.protocol,
                            src_port=s.src_port, dst_port=dst_port,
                        )
                        for s in services
                    ]

            rule = self._make_rule(
                raw_rule_id=rule_id,
                rule_name=f"{acl_name} rule {seq}",
                seq=len(rules),
                src_ip=src_addrs,
                dst_ip=dst_addrs,
                services=services,
                action=action,
                interface=acl_name,
                log_enabled=log_enabled,
            )
            rules.append(rule)

        return rules

    # ------------------------------------------------------------------
    # 辅助方法
    # ------------------------------------------------------------------

    def _parse_acl_service(
        self, rest: str, rule_id: str
    ) -> tuple[list[ServiceObject], str]:
        """从 ACL 行剩余部分解析服务/协议，返回（服务列表，剩余字符串）。"""
        tokens = rest.split()
        if not tokens:
            return self.object_store.resolve_service("any"), ""

        # object-group <name>（服务组）
        if tokens[0] == "object-group":
            if len(tokens) > 1:
                svcs = self.object_store.resolve_service(tokens[1])
                return svcs, " ".join(tokens[2:])

        # object <name>（单服务对象）
        if tokens[0] == "object":
            if len(tokens) > 1:
                svcs = self.object_store.resolve_service(tokens[1])
                return svcs, " ".join(tokens[2:])

        # 直接协议名
        proto = tokens[0].lower()
        if proto in ("ip", "tcp", "udp", "icmp", "icmp6", "gre", "esp", "ah", "ospf"):
            svc = ServiceObject(
                name=proto,
                protocol="any" if proto == "ip" else proto,
                src_port=PortRange.any(),
                dst_port=PortRange.any(),
            )
            return [svc], " ".join(tokens[1:])

        return self.object_store.resolve_service("any"), rest

    def _parse_acl_address_token(
        self, rest: str, rule_id: str, side: str
    ) -> tuple[list[AddressObject], str]:
        """从 ACL 行剩余部分解析一个地址标记，返回（地址列表，剩余字符串）。"""
        tokens = rest.split()
        if not tokens:
            return self.object_store.resolve_address("any"), ""

        # any
        if tokens[0] == "any" or tokens[0] == "any4":
            return self.object_store.resolve_address("any"), " ".join(tokens[1:])

        # host <ip>
        if tokens[0] == "host" and len(tokens) > 1:
            obj_name = f"inline_{side}_{tokens[1]}_host"
            self.object_store.add_address_object(obj_name, "host", tokens[1])
            return self.object_store.resolve_address(obj_name), " ".join(tokens[2:])

        # object-group <name>
        if tokens[0] == "object-group" and len(tokens) > 1:
            addrs = self.object_store.resolve_address(tokens[1])
            return addrs, " ".join(tokens[2:])

        # object <name>
        if tokens[0] == "object" and len(tokens) > 1:
            addrs = self.object_store.resolve_address(tokens[1])
            return addrs, " ".join(tokens[2:])

        # <ip> <mask>（subnet mask 格式）
        if (len(tokens) >= 2 and
                re.match(r"^\d+\.\d+\.\d+\.\d+$", tokens[0]) and
                re.match(r"^\d+\.\d+\.\d+\.\d+$", tokens[1])):
            obj_name = f"inline_{side}_{tokens[0]}_net"
            # Cisco ASA 使用 subnet mask
            self.object_store.add_address_object(obj_name, "subnet", tokens[0], tokens[1])
            return self.object_store.resolve_address(obj_name), " ".join(tokens[2:])

        # 单 IP（无掩码，视为 /32）
        if re.match(r"^\d+\.\d+\.\d+\.\d+(/\d+)?$", tokens[0]):
            obj_name = f"inline_{side}_{tokens[0]}"
            self.object_store.add_address_object(obj_name, "host", tokens[0])
            return self.object_store.resolve_address(obj_name), " ".join(tokens[1:])

        return self.object_store.resolve_address("any"), rest

    def _parse_inline_port(self, port_str: str) -> PortRange | None:
        """解析行内端口规格，如 'eq 443'、'range 80 443'、'lt 1024'。"""
        tokens = port_str.split()
        if not tokens:
            return None
        op = tokens[0].lower()
        if op == "eq" and len(tokens) > 1:
            port = self._resolve_port_name(tokens[1])
            return PortRange.single(port)
        if op == "range" and len(tokens) > 2:
            lo = self._resolve_port_name(tokens[1])
            hi = self._resolve_port_name(tokens[2])
            return PortRange(lo, hi)
        if op == "lt" and len(tokens) > 1:
            hi = self._resolve_port_name(tokens[1]) - 1
            return PortRange(0, hi)
        if op == "gt" and len(tokens) > 1:
            lo = self._resolve_port_name(tokens[1]) + 1
            return PortRange(lo, 65535)
        return None

    def _parse_asa_port_op(
        self, eq_val: str | None, range_lo: str | None, range_hi: str | None
    ) -> PortRange:
        """将 ASA object service 中的端口操作数解析为 PortRange。"""
        if eq_val:
            port = self._resolve_port_name(eq_val)
            return PortRange.single(port)
        if range_lo and range_hi:
            lo = self._resolve_port_name(range_lo)
            hi = self._resolve_port_name(range_hi)
            return PortRange(lo, hi)
        return PortRange.any()

    def _resolve_port_name(self, port_str: str) -> int:
        """将端口名称（如 'https'）或数字字符串转换为整数端口号。"""
        try:
            return int(port_str)
        except ValueError:
            return ASA_PORT_NAMES.get(port_str.lower(), 0)

    @staticmethod
    def _normalize_action(
        action: str,
    ) -> Literal["permit", "deny", "drop", "reject"]:
        a = action.lower()
        if a in ("permit", "allow", "accept"):
            return "permit"
        return "deny"
