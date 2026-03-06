"""
fw_analyzer/parsers/huawei.py

华为防火墙配置解析器。

支持的配置风格：
  1. 老版 ACL 格式（USG2000/5000 系列）
       acl number 3000
         rule 5 permit ip source 10.0.0.0 0.0.255.255 destination any
  2. 新版安全策略格式（USG6000/USG9000/NE 系列）
       security-policy
         rule name permit-web
           source-address address-group grp-web
           destination-address any
           service http https
           action permit

对象支持：
  ip address-group <name>        → 地址对象组
  service-group <name>           → 服务对象组
  ip service-set <name>          → 服务集合（新版）

注意：
  - address-group 中 address 关键字后跟 subnet mask（不是 wildcard）
  - acl rule 中 source/destination 后跟 wildcard mask
  - 通过解析所在块的上下文来区分
"""
from __future__ import annotations

import re
from typing import Literal

from .base import AbstractParser
from ..models.rule import FlatRule, Warning, WarningSeverity
from ..models.port_range import PortRange
from ..models.object_store import AddressObject, ServiceObject
from ..models.ip_utils import parse_ipv4_network, NonContiguousWildcardError


# 华为预定义服务名称映射
HUAWEI_BUILTIN_SERVICES: dict[str, tuple[str, int, int]] = {
    "http":     ("tcp", 80, 80),
    "https":    ("tcp", 443, 443),
    "ftp":      ("tcp", 21, 21),
    "ftp-data": ("tcp", 20, 20),
    "ssh":      ("tcp", 22, 22),
    "telnet":   ("tcp", 23, 23),
    "smtp":     ("tcp", 25, 25),
    "dns":      ("udp", 53, 53),
    "snmp":     ("udp", 161, 161),
    "snmptrap": ("udp", 162, 162),
    "ntp":      ("udp", 123, 123),
    "rdp":      ("tcp", 3389, 3389),
    "mysql":    ("tcp", 3306, 3306),
    "mssql":    ("tcp", 1433, 1433),
    "ping":     ("icmp", 0, 0),
    "icmp":     ("icmp", 0, 0),
}

# 华为配置中的名称可以是不含空格的单词，也可以是双引号括起的含空格字符串。
# 此正则捕获两种格式：(?:"([^"]+)"|(\S+))
# 使用 _extract_name() 辅助函数取出实际名称。
_NAME_RE = r'(?:"([^"]+)"|(\S+))'


def _extract_name(m: re.Match, group_quoted: int, group_bare: int) -> str:
    """从匹配中提取名称（优先 quoted，fallback bare）。"""
    return m.group(group_quoted) or m.group(group_bare)


class HuaweiParser(AbstractParser):
    """华为防火墙配置解析器。"""

    @property
    def vendor(self) -> str:
        return "huawei"

    # ------------------------------------------------------------------
    # 阶段1：解析对象定义
    # ------------------------------------------------------------------

    def _parse_objects(self, text: str) -> None:
        """解析华为配置中的所有对象定义。"""
        self._parse_address_groups(text)
        self._parse_address_sets(text)
        self._parse_service_groups(text)
        self._parse_ip_service_sets(text)
        # 注册内置服务
        for name, (proto, lo, hi) in HUAWEI_BUILTIN_SERVICES.items():
            if not self.object_store.has_service(name):
                self.object_store.add_service_object(
                    name, proto,
                    dst_port=PortRange(lo, hi),
                )

    def _parse_address_groups(self, text: str) -> None:
        """
        解析 ip address-group 块。

        格式：
          ip address-group <name>
            address <ip> mask <subnet_mask>
            address <ip> <prefix_len>
        """
        # 提取所有 ip address-group 块
        block_pattern = re.compile(
            r"^ip\s+address-group\s+(\S+)(.*?)(?=^ip\s+address-group\s|\Z)",
            re.MULTILINE | re.DOTALL,
        )
        for m in block_pattern.finditer(text):
            group_name = m.group(1)
            block = m.group(2)
            members: list[str] = []

            addr_pattern = re.compile(
                r"^\s+address\s+(\d+\.\d+\.\d+\.\d+)"
                r"(?:\s+mask\s+(\d+\.\d+\.\d+\.\d+)|\s+(\d+\.\d+\.\d+\.\d+)|/(\d+))?",
                re.MULTILINE,
            )
            for am in addr_pattern.finditer(block):
                ip = am.group(1)
                mask = am.group(2) or am.group(3)  # mask 关键字后 / 直接掩码
                prefix = am.group(4)
                obj_name = f"{group_name}_{ip}"
                if prefix:
                    self.object_store.add_address_object(obj_name, "subnet", f"{ip}/{prefix}")
                else:
                    # address-group 中使用 subnet mask（非 wildcard）
                    self.object_store.add_address_object(obj_name, "subnet", ip, mask)
                members.append(obj_name)

            if members:
                self.object_store.add_address_group(group_name, members)

    def _parse_address_sets(self, text: str) -> None:
        """
        解析 ip address-set 块（USG6000/USG9000 新版格式）。

        格式 type object（叶子，包含 IP 地址）：
          ip address-set <name> type object
            address <idx> <ip> mask <prefix_int_or_dotted_mask>
            address <idx> <ip> <bare_0>          # bare 0 = /32
            address <idx> range <start> <end>

        格式 type group（组，包含对其他 address-set 的引用）：
          ip address-set <name> type group
            address <idx> address-set <ref_name>
        """
        # 提取所有 ip address-set 块（以 # 或下一个 ip address-set / ip service-set 结束）
        block_pattern = re.compile(
            r"^ip\s+address-set\s+" + _NAME_RE + r"\s+type\s+(object|group)"
            r"(.*?)(?=^ip\s+(?:address-set|service-set)\s|\Z|^#$)",
            re.MULTILINE | re.DOTALL,
        )
        for m in block_pattern.finditer(text):
            set_name = m.group(1) or m.group(2)
            set_type = m.group(3)  # "object" or "group"
            block = m.group(4)

            if set_type == "group":
                # type group: 包含对其他 address-set 的引用
                members: list[str] = []
                for ref_m in re.finditer(
                    r"^\s+address\s+\d+\s+address-set\s+" + _NAME_RE,
                    block, re.MULTILINE,
                ):
                    members.append(ref_m.group(1) or ref_m.group(2))
                if members:
                    self.object_store.add_address_group(set_name, members)
            else:
                # type object: 包含具体 IP 地址
                members_obj: list[str] = []

                # address <idx> <ip> mask <prefix_int_or_dotted>
                for am in re.finditer(
                    r"^\s+address\s+\d+\s+(\d+\.\d+\.\d+\.\d+)\s+mask\s+(\S+)",
                    block, re.MULTILINE,
                ):
                    ip = am.group(1)
                    mask_val = am.group(2)
                    obj_name = f"{set_name}_{ip}"
                    if "." in mask_val:
                        # 点分掩码（如 255.255.255.0）— address-set 中为 subnet mask
                        self.object_store.add_address_object(
                            obj_name, "subnet", ip, mask_val,
                        )
                    else:
                        # 整数前缀（如 32、24）
                        self.object_store.add_address_object(
                            obj_name, "subnet", f"{ip}/{mask_val}",
                        )
                    members_obj.append(obj_name)

                # address <idx> <ip> 0  （bare 0 = host /32）
                for am in re.finditer(
                    r"^\s+address\s+\d+\s+(\d+\.\d+\.\d+\.\d+)\s+0\s*$",
                    block, re.MULTILINE,
                ):
                    ip = am.group(1)
                    obj_name = f"{set_name}_{ip}"
                    if obj_name not in [m for m in members_obj]:
                        self.object_store.add_address_object(
                            obj_name, "subnet", f"{ip}/32",
                        )
                        members_obj.append(obj_name)

                # address <idx> range <start_ip> <end_ip>
                for am in re.finditer(
                    r"^\s+address\s+\d+\s+range\s+"
                    r"(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)",
                    block, re.MULTILINE,
                ):
                    start_ip = am.group(1)
                    end_ip = am.group(2)
                    obj_name = f"{set_name}_{start_ip}-{end_ip}"
                    self.object_store.add_address_object(
                        obj_name, "range", f"{start_ip}-{end_ip}",
                    )
                    members_obj.append(obj_name)

                if members_obj:
                    self.object_store.add_address_group(set_name, members_obj)

    def _parse_service_groups(self, text: str) -> None:
        """
        解析 service-group 块（老版格式）。

        格式：
          service-group <name>
            service protocol tcp destination-port 80 to 443
            service protocol udp destination-port 53
        """
        block_pattern = re.compile(
            r"^service-group\s+(\S+)(.*?)(?=^service-group\s|\Z)",
            re.MULTILINE | re.DOTALL,
        )
        for m in block_pattern.finditer(text):
            group_name = m.group(1)
            block = m.group(2)
            members: list[str] = []

            svc_pattern = re.compile(
                r"^\s+service\s+protocol\s+(\w+)"
                r"(?:\s+source-port\s+(\d+)(?:\s+to\s+(\d+))?)?"
                r"(?:\s+destination-port\s+(\d+)(?:\s+to\s+(\d+))?)?",
                re.MULTILINE,
            )
            for sm in svc_pattern.finditer(block):
                proto = sm.group(1).lower()
                sp_lo = int(sm.group(2)) if sm.group(2) else 0
                sp_hi = int(sm.group(3)) if sm.group(3) else (sp_lo if sm.group(2) else 65535)
                dp_lo = int(sm.group(4)) if sm.group(4) else 0
                dp_hi = int(sm.group(5)) if sm.group(5) else (dp_lo if sm.group(4) else 65535)

                svc_name = f"{group_name}_{proto}_{dp_lo}_{dp_hi}"
                self.object_store.add_service_object(
                    svc_name, proto,
                    src_port=PortRange(sp_lo, sp_hi),
                    dst_port=PortRange(dp_lo, dp_hi),
                )
                members.append(svc_name)

            if members:
                self.object_store.add_service_group(group_name, members)

    def _parse_ip_service_sets(self, text: str) -> None:
        """
        解析 ip service-set 块（新版格式）。

        格式：
          ip service-set <name> type object
            service 0 protocol tcp destination-port 0 to 65535
        """
        block_pattern = re.compile(
            r"^ip\s+service-set\s+" + _NAME_RE + r"\s+type\s+object"
            r"(.*?)(?=^ip\s+service-set\s|\Z)",
            re.MULTILINE | re.DOTALL,
        )
        for m in block_pattern.finditer(text):
            set_name = m.group(1) or m.group(2)
            block = m.group(3)
            members: list[str] = []

            svc_pattern = re.compile(
                r"^\s+service\s+\d+\s+protocol\s+(\w+)"
                r"(?:\s+source-port\s+(\d+)(?:\s+to\s+(\d+))?)?"
                r"(?:\s+destination-port\s+(\d+)(?:\s+to\s+(\d+))?)?",
                re.MULTILINE,
            )
            for sm in svc_pattern.finditer(block):
                proto = sm.group(1).lower()
                sp_lo = int(sm.group(2)) if sm.group(2) else 0
                sp_hi = int(sm.group(3)) if sm.group(3) else (sp_lo if sm.group(2) else 65535)
                dp_lo = int(sm.group(4)) if sm.group(4) else 0
                dp_hi = int(sm.group(5)) if sm.group(5) else (dp_lo if sm.group(4) else 65535)

                svc_name = f"{set_name}_{proto}_{dp_lo}_{dp_hi}"
                self.object_store.add_service_object(
                    svc_name, proto,
                    src_port=PortRange(sp_lo, sp_hi),
                    dst_port=PortRange(dp_lo, dp_hi),
                )
                members.append(svc_name)

            if members:
                self.object_store.add_service_group(set_name, members)

    # ------------------------------------------------------------------
    # 阶段2：解析规则
    # ------------------------------------------------------------------

    def _parse_rules(self, text: str) -> list[FlatRule]:
        """解析华为配置中的所有防火墙策略规则。"""
        rules: list[FlatRule] = []

        # 优先尝试新版安全策略格式
        new_style = self._parse_security_policy(text)
        if new_style:
            rules.extend(new_style)

        # 再解析老版 interzone 策略格式
        old_style = self._parse_interzone_policy(text)
        if old_style:
            rules.extend(old_style)

        # 最后解析 ACL 格式
        acl_rules = self._parse_acl(text)
        if acl_rules:
            rules.extend(acl_rules)

        # 按 seq 重排
        rules.sort(key=lambda r: r.seq)
        return rules

    def _parse_security_policy(self, text: str) -> list[FlatRule]:
        """
        解析新版安全策略格式：
          security-policy
            rule name <name>
              source-zone <zone>
              destination-zone <zone>
              source-address address-group <grp> | ip-address <ip> <mask> | any
              destination-address address-group <grp> | ip-address <ip> <mask> | any
              service <svc> [<svc> ...]
              action permit|deny
        """
        rules: list[FlatRule] = []

        # 找到所有 security-policy 块（配置中可能有多个）
        sp_blocks: list[str] = []
        for sp_match in re.finditer(
            r"^security-policy$(.*?)(?=^\S|\Z)",
            text, re.MULTILINE | re.DOTALL,
        ):
            sp_blocks.append(sp_match.group(1))

        if not sp_blocks:
            return rules

        seq = 0

        for sp_block in sp_blocks:
            # 提取每个 rule 块
            rule_pattern = re.compile(
                r"^\s+rule\s+name\s+(\S+)(.*?)(?=^\s+rule\s+name\s+|\Z)",
                re.MULTILINE | re.DOTALL,
            )
            for rm in rule_pattern.finditer(sp_block):
                rule_name = rm.group(1)
                rule_block = rm.group(2)

                src_zone = self._extract_value(rule_block, r"source-zone\s+(\S+)")
                dst_zone = self._extract_value(rule_block, r"destination-zone\s+(\S+)")
                action_str = self._extract_value(rule_block, r"action\s+(permit|deny)")
                action = self._normalize_action(action_str or "deny")
                comment = self._extract_value(rule_block, r'description\s+"?([^"\n]+)"?') or ""
                enabled = "dis " not in rule_block.lower() and "undo rule" not in rule_block.lower()

                src_addrs = self._parse_address_field(rule_block, "source-address")
                dst_addrs = self._parse_address_field(rule_block, "destination-address")
                services = self._parse_service_field(rule_block)

                rule = self._make_rule(
                    raw_rule_id=rule_name,
                    rule_name=rule_name,
                    seq=seq,
                    src_ip=src_addrs,
                    dst_ip=dst_addrs,
                    services=services,
                    action=action,
                    src_zone=src_zone or "",
                    dst_zone=dst_zone or "",
                    enabled=enabled,
                    comment=comment,
                )
                rules.append(rule)
                seq += 1

        return rules

    def _parse_interzone_policy(self, text: str) -> list[FlatRule]:
        """
        解析老版 interzone 策略格式：
          firewall policy interzone <zone1> <zone2> <inbound|outbound>
            rule name <name>
              ...
        """
        rules: list[FlatRule] = []
        seq = 0

        block_pattern = re.compile(
            r"^firewall\s+policy\s+interzone\s+(\S+)\s+(\S+)\s+(inbound|outbound)"
            r"(.*?)(?=^firewall\s+policy\s+interzone\s+|\Z)",
            re.MULTILINE | re.DOTALL,
        )
        for bm in block_pattern.finditer(text):
            zone1, zone2 = bm.group(1), bm.group(2)
            direction = bm.group(3)
            block = bm.group(4)

            src_zone = zone1 if direction == "outbound" else zone2
            dst_zone = zone2 if direction == "outbound" else zone1

            rule_pattern = re.compile(
                r"^\s+rule\s+name\s+(\S+)(.*?)(?=^\s+rule\s+name\s+|\Z)",
                re.MULTILINE | re.DOTALL,
            )
            for rm in rule_pattern.finditer(block):
                rule_name = rm.group(1)
                rule_block = rm.group(2)

                action_str = self._extract_value(rule_block, r"action\s+(permit|deny)")
                action = self._normalize_action(action_str or "deny")
                comment = self._extract_value(rule_block, r'description\s+"?([^"\n]+)"?') or ""
                enabled = "dis " not in rule_block.lower()

                src_addrs = self._parse_address_field(rule_block, "source-address")
                dst_addrs = self._parse_address_field(rule_block, "destination-address")
                services = self._parse_service_field(rule_block)

                rule = self._make_rule(
                    raw_rule_id=rule_name,
                    rule_name=rule_name,
                    seq=seq,
                    src_ip=src_addrs,
                    dst_ip=dst_addrs,
                    services=services,
                    action=action,
                    src_zone=src_zone,
                    dst_zone=dst_zone,
                    direction=direction,  # type: ignore[arg-type]
                    enabled=enabled,
                    comment=comment,
                )
                rules.append(rule)
                seq += 1

        return rules

    def _parse_acl(self, text: str) -> list[FlatRule]:
        """
        解析老版 ACL 格式：
          acl number <num>
            rule <id> (permit|deny) [protocol]
              source <ip> <wildcard> | source address-set <name> | any
              destination <ip> <wildcard> | destination address-set <name> | any
              [source-port eq/range ...]
              [destination-port eq/range ...]
              [logging]

        支持三种子格式：
          1. 基本 ACL（无 protocol）: rule 5 permit source 10.0.0.1 0 logging
          2. 扩展 ACL: rule 5 permit tcp source 10.0.0.0 0.0.3.255 destination ...
          3. address-set 引用: rule 85 permit tcp source address-set <name> ...
        """
        rules: list[FlatRule] = []
        seq = 0

        acl_block_pattern = re.compile(
            r"^acl\s+(?:number\s+)?(\d+)(.*?)(?=^acl\s+|\Z)",
            re.MULTILINE | re.DOTALL,
        )
        for bm in acl_block_pattern.finditer(text):
            acl_id = bm.group(1)
            block = bm.group(2)

            # 匹配每条 rule 行
            rule_line_pattern = re.compile(
                r"^\s+rule\s+(\d+)\s+(permit|deny)\s+(.+?)\s*$",
                re.MULTILINE,
            )
            for rm in rule_line_pattern.finditer(block):
                rule_num = rm.group(1)
                rule_id = f"acl{acl_id}-rule{rule_num}"
                action = self._normalize_action(rm.group(2))
                rest = rm.group(3)  # 剩余内容

                proto, src_addrs, dst_addrs, dst_port = self._parse_acl_rule_body(
                    rest, rule_id
                )

                svc = ServiceObject(
                    name=proto,
                    protocol=proto if proto != "ip" else "any",
                    src_port=PortRange.any(),
                    dst_port=dst_port,
                )

                rule = self._make_rule(
                    raw_rule_id=rule_id,
                    rule_name=rule_id,
                    seq=seq,
                    src_ip=src_addrs,
                    dst_ip=dst_addrs,
                    services=[svc],
                    action=action,
                )
                rules.append(rule)
                seq += 1

        return rules

    def _parse_acl_rule_body(
        self, body: str, rule_id: str
    ) -> tuple[str, list[AddressObject], list[AddressObject], PortRange]:
        """
        解析 ACL 规则行的 action 之后的部分。

        返回 (protocol, src_addrs, dst_addrs, dst_port)。
        """
        # 剥离尾部 logging 关键字
        body = re.sub(r"\s+logging\s*$", "", body)

        # 检测 protocol：如果 body 以已知协议名开头，提取它
        proto_match = re.match(
            r"(ip|tcp|udp|icmp|ipinip|gre|ospf|igmp)\s+", body, re.IGNORECASE,
        )
        if proto_match:
            proto = proto_match.group(1).lower()
            body = body[proto_match.end():]
        else:
            proto = "ip"

        src_addrs: list[AddressObject] = self.object_store.resolve_address("any")
        dst_addrs: list[AddressObject] = self.object_store.resolve_address("any")
        dst_port = PortRange.any()

        # 解析 source 部分
        src_set_m = re.search(r"source\s+address-set\s+(\S+)", body)
        src_ip_m = re.search(r"source\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)", body)
        if src_set_m:
            src_addrs = self.object_store.resolve_address(src_set_m.group(1))
        elif src_ip_m:
            src_addrs = self._parse_acl_address(
                src_ip_m.group(1), src_ip_m.group(2), rule_id, "src"
            )

        # 解析 destination 部分
        dst_set_m = re.search(r"destination\s+address-set\s+(\S+)", body)
        dst_ip_m = re.search(
            r"destination\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)", body,
        )
        if dst_set_m:
            dst_addrs = self.object_store.resolve_address(dst_set_m.group(1))
        elif dst_ip_m:
            dst_addrs = self._parse_acl_address(
                dst_ip_m.group(1), dst_ip_m.group(2), rule_id, "dst"
            )

        # 解析 destination-port
        dp_eq_m = re.search(r"destination-port\s+eq\s+(\S+)", body)
        dp_range_m = re.search(r"destination-port\s+range\s+(\d+)\s+(\d+)", body)
        if dp_eq_m:
            port_val = dp_eq_m.group(1)
            port_num = self._resolve_port_name(port_val)
            dst_port = PortRange(port_num, port_num)
        elif dp_range_m:
            dst_port = PortRange(int(dp_range_m.group(1)), int(dp_range_m.group(2)))

        return proto, src_addrs, dst_addrs, dst_port

    @staticmethod
    def _resolve_port_name(port_str: str) -> int:
        """将端口名或数字字符串转换为整数。"""
        try:
            return int(port_str)
        except ValueError:
            # 华为常见端口名映射
            known_ports = {
                "ftp-data": 20, "ftp": 21, "ssh": 22, "telnet": 23,
                "smtp": 25, "dns": 53, "http": 80, "pop3": 110,
                "sunrpc": 111, "bgp": 179, "https": 443, "mssql": 1433,
                "mysql": 3306, "rdp": 3389,
            }
            return known_ports.get(port_str.lower(), 0)

    # ------------------------------------------------------------------
    # 辅助方法
    # ------------------------------------------------------------------

    def _parse_address_field(
        self, block: str, keyword: str
    ) -> list[AddressObject]:
        """
        解析规则块中的 source-address 或 destination-address 字段。

        支持：
          source-address any
          source-address address-group <grp>
          source-address address-set <set>      （新版 USG6000 格式）
          source-address ip-address <ip> <mask>/<prefix>
          source-address <ip> mask <mask>        （内联 IP + mask 格式）
        """
        addrs: list[AddressObject] = []

        # any
        if re.search(rf"{keyword}\s+any", block):
            return self.object_store.resolve_address("any")

        # address-group 引用（可多个）
        for m in re.finditer(rf"{keyword}\s+address-group\s+(\S+)", block):
            addrs.extend(self.object_store.resolve_address(m.group(1)))

        # address-set 引用（可多个，USG6000 新版格式，支持引号）
        for m in re.finditer(
            rf"{keyword}\s+address-set\s+" + _NAME_RE, block,
        ):
            addrs.extend(self.object_store.resolve_address(m.group(1) or m.group(2)))

        # ip-address 直接指定
        for m in re.finditer(
            rf"{keyword}\s+ip-address\s+(\d+\.\d+\.\d+\.\d+)"
            r"(?:\s+(\d+\.\d+\.\d+\.\d+)|/(\d+))?",
            block,
        ):
            ip = m.group(1)
            mask = m.group(2)
            prefix = m.group(3)
            obj_name = f"inline_{ip}"
            if prefix:
                self.object_store.add_address_object(obj_name, "subnet", f"{ip}/{prefix}")
            else:
                self.object_store.add_address_object(obj_name, "subnet", ip, mask)
            addrs.extend(self.object_store.resolve_address(obj_name))

        # 内联 IP + mask 格式：source-address <ip> mask <dotted_mask>
        for m in re.finditer(
            rf"{keyword}\s+(\d+\.\d+\.\d+\.\d+)\s+mask\s+(\d+\.\d+\.\d+\.\d+)",
            block,
        ):
            ip = m.group(1)
            mask = m.group(2)
            obj_name = f"inline_{ip}"
            self.object_store.add_address_object(obj_name, "subnet", ip, mask)
            addrs.extend(self.object_store.resolve_address(obj_name))

        return addrs if addrs else self.object_store.resolve_address("any")

    def _parse_service_field(self, block: str) -> list[ServiceObject]:
        """
        解析规则块中的 service 字段。

        支持：
          service any
          service <name>                     （每行一个服务名）
          service "<name with spaces>"       （引号名称）
          service service-set <name>
          service protocol <proto> ...       （ip service-set 内联格式，不在此处理）

        注意：一个规则块中可以有多行 service，需要用 finditer 遍历所有行。
        """
        services: list[ServiceObject] = []

        if re.search(r"^\s+service\s+any\s*$", block, re.MULTILINE):
            return self.object_store.resolve_service("any")

        # service-set 引用
        for m in re.finditer(r"^\s+service\s+service-set\s+(\S+)", block, re.MULTILINE):
            services.extend(self.object_store.resolve_service(m.group(1)))

        # 引号名称服务：service "name with spaces"
        for m in re.finditer(
            r'^\s+service\s+"([^"]+)"', block, re.MULTILINE,
        ):
            services.extend(self.object_store.resolve_service(m.group(1)))

        # 直接服务名（排除 service-set / any / protocol / 引号名称）
        for svc_line in re.finditer(
            r'^\s+service\s+(?!service-set\s|any\s|any$|protocol\s|")(\S+)',
            block, re.MULTILINE,
        ):
            services.extend(self.object_store.resolve_service(svc_line.group(1)))

        return services if services else self.object_store.resolve_service("any")

    def _parse_acl_address(
        self, ip_str: str, mask: str | None, rule_id: str, side: str
    ) -> list[AddressObject]:
        """解析 ACL 规则中的地址（使用 wildcard mask）。"""
        if ip_str.lower() == "any":
            return self.object_store.resolve_address("any")

        obj_name = f"acl_{rule_id}_{side}_{ip_str}"

        # 处理 bare 0（华为 ACL 中 0 = host /32，即 wildcard 0.0.0.0）
        if mask == "0":
            mask = "0.0.0.0"

        try:
            # ACL 中使用 wildcard mask
            self.object_store.add_address_object(obj_name, "subnet", ip_str, mask)
        except Exception:
            pass
        return self.object_store.resolve_address(obj_name)

    @staticmethod
    def _extract_value(text: str, pattern: str) -> str | None:
        m = re.search(pattern, text, re.MULTILINE | re.IGNORECASE)
        return m.group(1).strip() if m else None

    @staticmethod
    def _normalize_action(
        action: str,
    ) -> Literal["permit", "deny", "drop", "reject"]:
        a = action.lower()
        if a in ("permit", "allow", "accept", "pass"):
            return "permit"
        if a in ("drop", "discard"):
            return "drop"
        if a == "reject":
            return "reject"
        return "deny"
