"""
fw_analyzer/parsers/fortinet.py

Fortinet FortiGate 配置解析器（层级文本格式）。

FortiGate 使用层级缩进文本格式：
  config firewall address
      edit "web-server"
          set subnet 10.0.0.1 255.255.255.255
      next
  end

  config firewall addrgrp
      edit "grp-web"
          set member "web-server" "db-server"
      next
  end

  config firewall service custom
      edit "HTTPS"
          set tcp-portrange 443
      next
  end

  config firewall service group
      edit "svc-grp"
          set member "HTTPS" "HTTP"
      next
  end

  config firewall policy
      edit 1
          set name "permit-web"
          set srcintf "inside"
          set dstintf "outside"
          set srcaddr "grp-web"
          set dstaddr "all"
          set service "HTTPS"
          set action accept
          set status enable
          set comments "web traffic"
      next
  end

注意：
  - 使用状态机解析，逐行处理
  - 支持 config/edit/set/next/end 关键字
  - subnet 字段使用 Subnet Mask 格式
  - range 字段格式：start-ip end-ip
  - tcp-portrange / udp-portrange 格式：port 或 port-range 或 src:dst
  - status disable → enabled=False
"""
from __future__ import annotations

import re
import shlex
from typing import Literal

from .base import AbstractParser
from ..models.rule import FlatRule, Warning, WarningSeverity, ParseResult
from ..models.port_range import PortRange
from ..models.object_store import AddressObject, ServiceObject
from ..models.ip_utils import parse_ipv4_network, NonContiguousWildcardError


# Fortinet 内置服务名称映射
FORTINET_BUILTIN_SERVICES: dict[str, list[tuple[str, int, int]]] = {
    "HTTP":     [("tcp", 80, 80)],
    "HTTPS":    [("tcp", 443, 443)],
    "FTP":      [("tcp", 21, 21)],
    "FTP_PUT":  [("tcp", 21, 21)],
    "SSH":      [("tcp", 22, 22)],
    "TELNET":   [("tcp", 23, 23)],
    "SMTP":     [("tcp", 25, 25)],
    "SMTPS":    [("tcp", 465, 465)],
    "DNS":      [("udp", 53, 53), ("tcp", 53, 53)],
    "SNMP":     [("udp", 161, 161)],
    "SNMPTRAP": [("udp", 162, 162)],
    "RDP":      [("tcp", 3389, 3389)],
    "MySQL":    [("tcp", 3306, 3306)],
    "MS-SQL":   [("tcp", 1433, 1433)],
    "PING":     [("icmp", 0, 0)],
    "ICMP":     [("icmp", 0, 0)],
    "NTP":      [("udp", 123, 123)],
    "SYSLOG":   [("udp", 514, 514)],
    "LDAP":     [("tcp", 389, 389)],
    "LDAPS":    [("tcp", 636, 636)],
    "ALL":      [],  # any
    "ALL_TCP":  [("tcp", 0, 65535)],
    "ALL_UDP":  [("udp", 0, 65535)],
    "ALL_ICMP": [("icmp", 0, 0)],
}


def _split_set_values(line: str) -> list[str]:
    """
    解析 FortiGate set 命令的值列表。

    FortiGate 中引号包围的名称（如 "grp-web"）和不带引号的值都需处理。
    使用 shlex 分割但容错处理引号不匹配情况。
    """
    try:
        parts = shlex.split(line)
    except ValueError:
        # 引号不匹配时退回简单分割
        parts = line.split()
    return [p.strip('"') for p in parts if p.strip('"')]


def _parse_portrange(portrange: str) -> list[PortRange]:
    """
    解析 FortiGate tcp-portrange / udp-portrange 字段。

    格式：
      "443"           → [PortRange(443, 443)]
      "80-8080"       → [PortRange(80, 8080)]
      "1024:443"      → src=1024, dst=443  → 返回 dst PortRange
      "1024-2048:443-8080" → src=1024-2048, dst=443-8080
      "80 443 8080"   → [PortRange(80,80), PortRange(443,443), PortRange(8080,8080)]
    """
    result: list[PortRange] = []
    # 可能有多个空格分隔的端口段
    for seg in portrange.strip().split():
        # 冒号分隔 src:dst
        if ":" in seg:
            parts = seg.split(":", 1)
            dst_part = parts[1]
        else:
            dst_part = seg

        # 解析 dst 部分（支持范围）
        m = re.match(r"^(\d+)(?:-(\d+))?$", dst_part)
        if m:
            lo = int(m.group(1))
            hi = int(m.group(2)) if m.group(2) else lo
            result.append(PortRange(lo, hi))

    return result or [PortRange.any()]


class FortinetParser(AbstractParser):
    """Fortinet FortiGate 层级文本配置解析器。"""

    @property
    def vendor(self) -> str:
        return "fortinet"

    # ------------------------------------------------------------------
    # 层级文本解析器核心
    # ------------------------------------------------------------------

    def _tokenize(self, text: str) -> list[dict]:
        """
        将 FortiGate 配置文本解析为结构化块列表。

        返回格式：
          [
            {"type": "config", "path": ["firewall", "address"], "children": [
              {"type": "edit", "name": "web-server", "sets": {"subnet": "10.0.0.1 255.255.255.255"}},
              ...
            ]},
            ...
          ]
        """
        lines = text.splitlines()
        return self._parse_block(lines, 0)[0]

    def _parse_block(self, lines: list[str], pos: int) -> tuple[list[dict], int]:
        """
        递归解析一个配置块，返回 (块列表, 解析到的行号)。
        """
        result: list[dict] = []
        i = pos

        while i < len(lines):
            line = lines[i].strip()

            if not line or line.startswith("#"):
                i += 1
                continue

            tokens = line.split()
            if not tokens:
                i += 1
                continue

            keyword = tokens[0].lower()

            if keyword == "config":
                path = tokens[1:]
                i += 1
                children, i = self._parse_block(lines, i)
                result.append({
                    "type": "config",
                    "path": path,
                    "children": children,
                })

            elif keyword == "edit":
                name = " ".join(tokens[1:]).strip('"') if len(tokens) > 1 else ""
                sets: dict[str, str] = {}
                children_in_edit: list[dict] = []
                i += 1
                # 收集 set 命令直到 next 或 end
                while i < len(lines):
                    inner = lines[i].strip()
                    if not inner or inner.startswith("#"):
                        i += 1
                        continue
                    inner_tokens = inner.split()
                    if not inner_tokens:
                        i += 1
                        continue
                    inner_kw = inner_tokens[0].lower()
                    if inner_kw in ("next", "end"):
                        break
                    if inner_kw == "set" and len(inner_tokens) >= 2:
                        key = inner_tokens[1].lower()
                        val = " ".join(inner_tokens[2:])
                        sets[key] = val
                        i += 1
                    elif inner_kw == "config":
                        # 嵌套 config（如 vdom 内的 config firewall address）
                        # 递归解析而不是跳过
                        path = inner_tokens[1:]
                        i += 1
                        nested_children, i = self._parse_block(lines, i)
                        children_in_edit.append({
                            "type": "config",
                            "path": path,
                            "children": nested_children,
                        })
                    else:
                        i += 1

                result.append({
                    "type": "edit",
                    "name": name,
                    "sets": sets,
                    "children": children_in_edit,
                })
                # 消耗 next/end
                if i < len(lines):
                    inner = lines[i].strip().split()
                    if inner and inner[0].lower() in ("next", "end"):
                        i += 1

            elif keyword == "end":
                i += 1
                break

            elif keyword == "next":
                i += 1
                break

            else:
                i += 1

        return result, i

    def _find_blocks(self, blocks: list[dict], *path_parts: str) -> list[dict]:
        """
        在解析后的块列表中查找匹配路径的 config 块的 children。
        递归搜索，以支持 config vdom / edit root 等顶层包装。

        例如：_find_blocks(blocks, "firewall", "address")
        """
        search = [p.lower() for p in path_parts]
        for block in blocks:
            if block["type"] == "config":
                bp = [p.lower() for p in block["path"]]
                if bp == search:
                    return block["children"]
                # 递归搜索 children（config 块的 children 包含 edit 和 config 子块）
                found = self._find_blocks(block["children"], *path_parts)
                if found:
                    return found
            elif block["type"] == "edit":
                # edit 块可能含有嵌套 config（如 vdom 中的 edit root）
                nested = block.get("children", [])
                if nested:
                    found = self._find_blocks(nested, *path_parts)
                    if found:
                        return found
        return []

    # ------------------------------------------------------------------
    # 阶段1：解析对象定义
    # ------------------------------------------------------------------

    def _parse_objects(self, text: str) -> None:
        """解析 FortiGate 配置中的所有对象定义。"""
        blocks = self._tokenize(text)

        self._parse_fw_addresses(blocks)
        self._parse_fw_addrgrps(blocks)
        self._parse_fw_services(blocks)
        self._parse_fw_service_groups(blocks)

        # 注册内置服务
        for name, ports in FORTINET_BUILTIN_SERVICES.items():
            if not self.object_store.has_service(name):
                if not ports:
                    # ALL → any（空 services 列表在 FlatRule 中显示为 any）
                    pass
                else:
                    for proto, lo, hi in ports:
                        self.object_store.add_service_object(
                            name, proto,
                            dst_port=PortRange(lo, hi),
                        )

    def _parse_fw_addresses(self, blocks: list[dict]) -> None:
        """解析 config firewall address。"""
        entries = self._find_blocks(blocks, "firewall", "address")
        for entry in entries:
            if entry["type"] != "edit":
                continue
            name = entry["name"]
            sets = entry["sets"]
            self._register_address(name, sets)

    def _register_address(self, name: str, sets: dict[str, str]) -> None:
        """根据 set 字典注册一个地址对象。"""
        addr_type = sets.get("type", "ipmask").lower()

        if addr_type in ("ipmask", "subnet", "") or "subnet" in sets:
            subnet_val = sets.get("subnet", "")
            if subnet_val:
                parts = subnet_val.strip().split()
                if len(parts) == 2:
                    ip, mask = parts
                    try:
                        self.object_store.add_address_object(name, "subnet", ip, mask)
                    except Exception:
                        self.object_store.add_address_object(name, "unknown", subnet_val)
                elif len(parts) == 1:
                    self.object_store.add_address_object(name, "subnet", parts[0])
                else:
                    self.object_store.add_address_object(name, "unknown", subnet_val)
            else:
                # 空 subnet = any（all 对象）
                self.object_store.add_address_object(name, "any", "0.0.0.0/0")

        elif addr_type == "iprange":
            start = sets.get("start-ip", "")
            end = sets.get("end-ip", "")
            if start and end:
                self.object_store.add_address_object(name, "range", f"{start}-{end}")
            else:
                self.object_store.add_address_object(name, "unknown", name)

        elif addr_type == "fqdn":
            fqdn_val = sets.get("fqdn", name)
            self.object_store.add_address_object(name, "fqdn", fqdn_val)

        elif addr_type == "wildcard-fqdn":
            fqdn_val = sets.get("wildcard-fqdn", name)
            self.object_store.add_address_object(name, "fqdn", f"*.{fqdn_val}")

        elif addr_type == "geography":
            # 地理位置对象，无法展开为 IP，标记为 unknown
            country = sets.get("country", name)
            self.object_store.add_address_object(name, "unknown", f"geo:{country}")

        else:
            self.object_store.add_address_object(name, "unknown", name)

    def _parse_fw_addrgrps(self, blocks: list[dict]) -> None:
        """解析 config firewall addrgrp。"""
        entries = self._find_blocks(blocks, "firewall", "addrgrp")
        for entry in entries:
            if entry["type"] != "edit":
                continue
            name = entry["name"]
            sets = entry["sets"]
            member_str = sets.get("member", "")
            members = _split_set_values(member_str) if member_str else []
            self.object_store.add_address_group(name, members)

    def _parse_fw_services(self, blocks: list[dict]) -> None:
        """解析 config firewall service custom。"""
        # FortiGate 服务在 config firewall service custom 下
        entries = self._find_blocks(blocks, "firewall", "service", "custom")
        for entry in entries:
            if entry["type"] != "edit":
                continue
            name = entry["name"]
            sets = entry["sets"]
            self._register_service(name, sets)

    def _register_service(self, name: str, sets: dict[str, str]) -> None:
        """根据 set 字典注册一个服务对象。"""
        proto_num = sets.get("protocol-number", "")
        proto_name = sets.get("protocol", "").lower()

        tcp_portrange = sets.get("tcp-portrange", "")
        udp_portrange = sets.get("udp-portrange", "")
        sctp_portrange = sets.get("sctp-portrange", "")

        if tcp_portrange:
            for pr in _parse_portrange(tcp_portrange):
                self.object_store.add_service_object(name, "tcp", dst_port=pr)
        if udp_portrange:
            for pr in _parse_portrange(udp_portrange):
                self.object_store.add_service_object(name, "udp", dst_port=pr)
        if sctp_portrange:
            for pr in _parse_portrange(sctp_portrange):
                self.object_store.add_service_object(name, "sctp", dst_port=pr)

        if not tcp_portrange and not udp_portrange and not sctp_portrange:
            if proto_name in ("icmp", "icmp6"):
                self.object_store.add_service_object(name, "icmp", dst_port=PortRange.any())
            elif proto_name == "ip":
                self.object_store.add_service_object(name, "any", dst_port=PortRange.any())
            else:
                # 默认作为 any
                self.object_store.add_service_object(name, "any", dst_port=PortRange.any())

    def _parse_fw_service_groups(self, blocks: list[dict]) -> None:
        """解析 config firewall service group。"""
        entries = self._find_blocks(blocks, "firewall", "service", "group")
        for entry in entries:
            if entry["type"] != "edit":
                continue
            name = entry["name"]
            sets = entry["sets"]
            member_str = sets.get("member", "")
            members = _split_set_values(member_str) if member_str else []
            self.object_store.add_service_group(name, members)

    # ------------------------------------------------------------------
    # 阶段2：解析防火墙策略
    # ------------------------------------------------------------------

    def _parse_rules(self, text: str) -> list[FlatRule]:
        """解析 FortiGate 防火墙策略。"""
        blocks = self._tokenize(text)
        rules: list[FlatRule] = []

        # 预提取原始 edit 块文本（用于 raw_config）
        raw_edit_blocks = self._extract_raw_edit_blocks(text)

        # config firewall policy
        policy_entries = self._find_blocks(blocks, "firewall", "policy")
        for entry in policy_entries:
            if entry["type"] != "edit":
                continue
            raw_config = raw_edit_blocks.get(entry["name"], "")
            rule = self._parse_policy_entry(entry, len(rules), raw_config=raw_config)
            if rule:
                rules.append(rule)

        # config firewall policy6（IPv6，跳过）
        # config firewall policy64 / policy46（跨版本，跳过）

        return rules

    @staticmethod
    def _extract_raw_edit_blocks(text: str) -> dict[str, str]:
        """从原始配置文本中提取 'config firewall policy' 内的 edit 块原文。

        返回 {policy_id: raw_text} 映射。
        """
        result: dict[str, str] = {}
        # 定位 config firewall policy ... end 段
        policy_section_re = re.compile(
            r"^config\s+firewall\s+policy\s*$(.*?)^end\s*$",
            re.MULTILINE | re.DOTALL,
        )
        for sec_m in policy_section_re.finditer(text):
            section = sec_m.group(1)
            # 提取每个 edit N ... next 块
            edit_re = re.compile(
                r"(^\s*edit\s+(\S+)\s*$.*?)(?=^\s*edit\s+\S+\s*$|^\s*end\s*$|\Z)",
                re.MULTILINE | re.DOTALL,
            )
            for em in edit_re.finditer(section):
                policy_id = em.group(2).strip('"')
                raw_block = em.group(1).strip()
                result[policy_id] = raw_block
        return result

    def _parse_policy_entry(self, entry: dict, seq: int, *, raw_config: str = "") -> FlatRule | None:
        """解析单条防火墙策略。"""
        raw_id = entry["name"]  # FortiGate 策略 ID 为数字字符串
        sets = entry["sets"]
        rule_warnings: list[Warning] = []

        # --- 策略名称 ---
        policy_name = sets.get("name", raw_id)

        # --- 启用/禁用 ---
        status = sets.get("status", "enable").lower()
        enabled = status != "disable"

        # --- 动作 ---
        action_str = sets.get("action", "deny").lower()
        if action_str == "accept":
            action: Literal["permit", "deny", "drop", "reject"] = "permit"
        elif action_str in ("deny", "drop"):
            action = "drop"
        else:
            action = "deny"

        # --- 接口/Zone ---
        src_intf = sets.get("srcintf", "")
        dst_intf = sets.get("dstintf", "")
        # FortiGate 接口名可含引号，已在 _split_set_values 中处理
        src_intfs = _split_set_values(src_intf) if src_intf else []
        dst_intfs = _split_set_values(dst_intf) if dst_intf else []

        # --- 源地址 ---
        srcaddr_str = sets.get("srcaddr", "")
        srcaddr_names = _split_set_values(srcaddr_str) if srcaddr_str else ["all"]
        if not srcaddr_names:
            srcaddr_names = ["all"]

        # --- 目的地址 ---
        dstaddr_str = sets.get("dstaddr", "")
        dstaddr_names = _split_set_values(dstaddr_str) if dstaddr_str else ["all"]
        if not dstaddr_names:
            dstaddr_names = ["all"]

        # --- 服务 ---
        service_str = sets.get("service", "")
        service_names = _split_set_values(service_str) if service_str else ["ALL"]
        if not service_names:
            service_names = ["ALL"]

        # --- 注释 ---
        comment = sets.get("comments", "").strip('"')

        # --- 日志 ---
        logtraffic = sets.get("logtraffic", "").lower()
        # FortiGate: "all"/"utm" = 有日志，"disable"/缺失 = 无日志
        log_enabled = logtraffic in ("all", "utm")

        # --- 展开地址 ---
        from ..models.ip_utils import parse_ipv4_network as _parse_net
        from ..models.object_store import AddressObject as _AO

        def resolve_fortinet_addr(names: list[str]) -> list[AddressObject]:
            if names in (["all"], ["any"]):
                return [_AO(
                    name="any", type="any", value="0.0.0.0/0",
                    network=_parse_net("0.0.0.0/0"),
                )]
            result: list[AddressObject] = []
            seen: set[str] = set()
            for n in names:
                if n.lower() in ("all", "any"):
                    return [_AO(
                        name="any", type="any", value="0.0.0.0/0",
                        network=_parse_net("0.0.0.0/0"),
                    )]
                for obj in self.object_store.resolve_address(n):
                    if obj.value not in seen:
                        seen.add(obj.value)
                        result.append(obj)
            return result

        src_ip = resolve_fortinet_addr(srcaddr_names)
        dst_ip = resolve_fortinet_addr(dstaddr_names)

        # --- 展开服务 ---
        def resolve_fortinet_svc(names: list[str]) -> list[ServiceObject]:
            if names in (["ALL"], ["all"], ["any"]):
                return []  # any
            result: list[ServiceObject] = []
            seen: set[str] = set()
            for n in names:
                if n.upper() in ("ALL", "ANY"):
                    return []
                for obj in self.object_store.resolve_service(n):
                    key = str(obj)
                    if key not in seen:
                        seen.add(key)
                        result.append(obj)
            return result

        services = resolve_fortinet_svc(service_names)

        # 转移 object_store 警告
        for sw in self.object_store.warnings:
            rule_warnings.append(Warning.from_store_warning(sw))
        self.object_store.warnings.clear()

        # --- referenced_objects ---
        ref_objects: list[str] = []
        for n in srcaddr_names:
            if n.lower() not in ("all", "any") and n not in ref_objects:
                ref_objects.append(n)
        for n in dstaddr_names:
            if n.lower() not in ("all", "any") and n not in ref_objects:
                ref_objects.append(n)
        for n in service_names:
            if n.upper() not in ("ALL", "ANY") and n not in ref_objects:
                ref_objects.append(n)

        return FlatRule(
            vendor=self.vendor,
            raw_rule_id=raw_id,
            rule_name=policy_name,
            seq=seq,
            src_ip=src_ip,
            dst_ip=dst_ip,
            services=services,
            action=action,
            src_zone="; ".join(src_intfs),
            dst_zone="; ".join(dst_intfs),
            enabled=enabled,
            log_enabled=log_enabled,
            comment=comment,
            warnings=rule_warnings,
            raw_config=raw_config,
            referenced_objects=ref_objects,
        )

    # AbstractParser 的两阶段接口由基类 parse() 统一调度，此处无需覆盖。
