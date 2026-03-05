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
    "rdp":      ("tcp", 3389, 3389),
    "mysql":    ("tcp", 3306, 3306),
    "mssql":    ("tcp", 1433, 1433),
    "ping":     ("icmp", 0, 0),
    "icmp":     ("icmp", 0, 0),
}


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
            r"^ip\s+service-set\s+(\S+)\s+type\s+object(.*?)(?=^ip\s+service-set\s|\Z)",
            re.MULTILINE | re.DOTALL,
        )
        for m in block_pattern.finditer(text):
            set_name = m.group(1)
            block = m.group(2)
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

        # 找到 security-policy 块
        sp_match = re.search(
            r"^security-policy$(.*?)(?=^\S|\Z)",
            text, re.MULTILINE | re.DOTALL,
        )
        if not sp_match:
            return rules

        sp_block = sp_match.group(1)
        seq = 0

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
            rule <id> (permit|deny) (ip|tcp|udp|icmp)
              source <ip> <wildcard> | any
              destination <ip> <wildcard> | any
              [source-port eq/range ...]
              [destination-port eq/range ...]
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

            # 单行规则格式（扩展 ACL）
            rule_pattern = re.compile(
                r"^\s+rule\s+(\d+)\s+(permit|deny)\s+(\S+)"
                r"(?:\s+source\s+(\S+)(?:\s+(\S+))?)?"
                r"(?:\s+destination\s+(\S+)(?:\s+(\S+))?)?",
                re.MULTILINE,
            )
            for rm in rule_pattern.finditer(block):
                rule_id = f"acl{acl_id}-rule{rm.group(1)}"
                action = self._normalize_action(rm.group(2))
                proto = rm.group(3).lower()

                src_ip_str = rm.group(4) or "any"
                src_mask = rm.group(5)
                dst_ip_str = rm.group(6) or "any"
                dst_mask = rm.group(7)

                src_addrs = self._parse_acl_address(src_ip_str, src_mask, rule_id, "src")
                dst_addrs = self._parse_acl_address(dst_ip_str, dst_mask, rule_id, "dst")

                svc = ServiceObject(
                    name=proto,
                    protocol=proto if proto != "ip" else "any",
                    src_port=PortRange.any(),
                    dst_port=PortRange.any(),
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
          source-address ip-address <ip> <mask>/<prefix>
          source-address <ip> <mask>  （部分简写格式）
        """
        addrs: list[AddressObject] = []

        # any
        if re.search(rf"{keyword}\s+any", block):
            return self.object_store.resolve_address("any")

        # address-group 引用（可多个）
        for m in re.finditer(rf"{keyword}\s+address-group\s+(\S+)", block):
            addrs.extend(self.object_store.resolve_address(m.group(1)))

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

        return addrs if addrs else self.object_store.resolve_address("any")

    def _parse_service_field(self, block: str) -> list[ServiceObject]:
        """
        解析规则块中的 service 字段。

        支持：
          service any
          service <name> [<name> ...]
          service service-set <name>
        """
        services: list[ServiceObject] = []

        if re.search(r"service\s+any", block):
            return self.object_store.resolve_service("any")

        # service-set 引用
        for m in re.finditer(r"service\s+service-set\s+(\S+)", block):
            services.extend(self.object_store.resolve_service(m.group(1)))

        # 直接服务名（可多个空格分隔）
        svc_line = re.search(r"^\s+service\s+(?!service-set|any)(.+)$", block, re.MULTILINE)
        if svc_line:
            for name in svc_line.group(1).split():
                services.extend(self.object_store.resolve_service(name))

        return services if services else self.object_store.resolve_service("any")

    def _parse_acl_address(
        self, ip_str: str, mask: str | None, rule_id: str, side: str
    ) -> list[AddressObject]:
        """解析 ACL 规则中的地址（使用 wildcard mask）。"""
        if ip_str.lower() == "any":
            return self.object_store.resolve_address("any")

        obj_name = f"acl_{rule_id}_{side}_{ip_str}"
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
