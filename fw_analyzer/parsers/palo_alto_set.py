"""
fw_analyzer/parsers/palo_alto_set.py

Palo Alto PAN-OS 配置解析器（set 命令格式）。

支持以下配置结构：
  set address <name> (ip-netmask|ip-range|fqdn) <value>
  set address-group <name> static [ member1 member2 ... ]
  set service <name> protocol (tcp|udp) port <port>
  set service-group <name> members [ member1 member2 ... ]
  set rulebase security rules <name> <property> <value>

名称可以被双引号包裹（当包含空格时），如：
  set rulebase security rules "Deny ACL" action deny
  set service "TCP 8443" protocol tcp port 8443

值可以是方括号列表：
  set rulebase security rules foo source [ 10.0.0.1 10.0.0.2 ]
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Literal

from .base import AbstractParser
from ..models.rule import FlatRule, Warning, WarningSeverity
from ..models.port_range import PortRange
from ..models.object_store import AddressObject, ServiceObject
from ..models.ip_utils import parse_ipv4_network

from .palo_alto import PANOS_BUILTIN_SERVICES, PANOS_APP_TO_PROTOCOL

# IP 字面量正则：裸 IP 或 CIDR
_IP_LITERAL_RE = re.compile(
    r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?$"
)


# ---------------------------------------------------------------
# Token 解析
# ---------------------------------------------------------------

# 匹配一个 token：双引号字符串或非空白序列
_TOKEN_RE = re.compile(r'"([^"]*)"|([\S]+)')


def _tokenize_line(line: str) -> list[str]:
    """
    将一行 set 命令拆分为 token 列表。

    双引号内的文本作为单个 token（不含引号）。
    方括号 `[` 和 `]` 作为独立 token。

    例：
      'set address "tm- 1.2.3.4" ip-netmask 1.2.3.4'
      → ['set', 'address', 'tm- 1.2.3.4', 'ip-netmask', '1.2.3.4']

      'set rulebase security rules foo source [ 10.0.0.1 10.0.0.2 ]'
      → ['set', 'rulebase', 'security', 'rules', 'foo', 'source', '[', '10.0.0.1', '10.0.0.2', ']']
    """
    tokens: list[str] = []
    for m in _TOKEN_RE.finditer(line):
        quoted = m.group(1)
        bare = m.group(2)
        if quoted is not None:
            tokens.append(quoted)
        elif bare is not None:
            # 方括号可能粘连：如 "[val" 或 "val]"，需要拆分
            # 但实际 PAN-OS 导出总是 "[ val1 val2 ]" 空格分隔
            tokens.append(bare)
    return tokens


def _collect_value(tokens: list[str], start: int) -> list[str]:
    """
    从 tokens[start] 开始收集值。

    如果 tokens[start] == '['，返回直到 ']' 之间的所有 token。
    否则返回单个 token 作为列表。
    """
    if start >= len(tokens):
        return []
    if tokens[start] == "[":
        result: list[str] = []
        i = start + 1
        while i < len(tokens) and tokens[i] != "]":
            result.append(tokens[i])
            i += 1
        return result
    return [tokens[start]]


class PaloAltoSetParser(AbstractParser):
    """Palo Alto PAN-OS set 命令格式配置解析器。"""

    @property
    def vendor(self) -> str:
        return "paloalto"

    # ------------------------------------------------------------------
    # 阶段1：解析对象定义
    # ------------------------------------------------------------------

    def _parse_objects(self, text: str) -> None:
        """解析 set 格式配置中的所有对象定义。"""
        # 收集每个对象的属性（多行 set 命令聚合）
        addresses: dict[str, dict[str, str]] = defaultdict(dict)
        address_groups: dict[str, list[str]] = {}
        services: dict[str, dict[str, str]] = defaultdict(dict)
        service_groups: dict[str, list[str]] = {}

        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("set "):
                continue

            tokens = _tokenize_line(line)
            if len(tokens) < 3:
                continue

            # set address <name> ...
            if tokens[1] == "address" and tokens[2] != "address-group":
                if len(tokens) < 4:
                    continue
                # 区分 "set address <name>" vs "set address-group <name>"
                # tokens[1] == "address" already checked above
                name = tokens[2]
                if len(tokens) >= 5:
                    prop = tokens[3]
                    val = tokens[4] if len(tokens) > 4 else ""
                    if prop in ("ip-netmask", "ip-range", "fqdn"):
                        addresses[name][prop] = val

            # set address-group <name> static [ ... ]
            elif len(tokens) >= 2 and tokens[1] == "address-group":
                if len(tokens) < 4:
                    continue
                name = tokens[2]
                prop = tokens[3]
                if prop == "static":
                    members = _collect_value(tokens, 4)
                    if name in address_groups:
                        address_groups[name].extend(members)
                    else:
                        address_groups[name] = members

            # set service <name> protocol (tcp|udp) (port|source-port|override) <val>
            elif tokens[1] == "service" and tokens[2] != "service-group":
                if len(tokens) < 4:
                    continue
                name = tokens[2]
                # tokens[3] should be "protocol"
                if tokens[3] == "protocol" and len(tokens) >= 5:
                    proto = tokens[4]  # tcp or udp
                    services[name]["protocol"] = proto
                    if len(tokens) >= 7:
                        sub_prop = tokens[5]  # port, source-port, override
                        sub_val = tokens[6]
                        if sub_prop == "port":
                            services[name]["port"] = sub_val
                        elif sub_prop == "source-port":
                            services[name]["source-port"] = sub_val

            # set service-group <name> members [ ... ]
            elif len(tokens) >= 2 and tokens[1] == "service-group":
                if len(tokens) < 4:
                    continue
                name = tokens[2]
                if tokens[3] == "members":
                    members = _collect_value(tokens, 4)
                    service_groups[name] = members

        # 注册地址对象
        for name, props in addresses.items():
            if "ip-netmask" in props:
                val = props["ip-netmask"]
                try:
                    self.object_store.add_address_object(name, "subnet", val)
                except Exception:
                    self.object_store.add_address_object(name, "unknown", val)
            elif "ip-range" in props:
                self.object_store.add_address_object(name, "range", props["ip-range"])
            elif "fqdn" in props:
                self.object_store.add_address_object(name, "fqdn", props["fqdn"])
            else:
                self.object_store.add_address_object(name, "unknown", name)

        # 注册地址组
        for name, members in address_groups.items():
            self.object_store.add_address_group(name, members)

        # 注册服务对象
        for name, props in services.items():
            proto = props.get("protocol", "tcp")
            port_text = props.get("port", "any")
            src_port_text = props.get("source-port", "any")
            dst_pr = self._parse_panos_port(port_text)
            src_pr = self._parse_panos_port(src_port_text)
            self.object_store.add_service_object(name, proto, dst_port=dst_pr, src_port=src_pr)

        # 注册服务组
        for name, members in service_groups.items():
            self.object_store.add_service_group(name, members)

        # 注册内置服务（不覆盖配置中已定义的同名服务）
        for name, ports in PANOS_BUILTIN_SERVICES.items():
            if not self.object_store.has_service(name):
                for proto, lo, hi in ports:
                    self.object_store.add_service_object(
                        name, proto,
                        dst_port=PortRange(lo, hi),
                    )

    # ------------------------------------------------------------------
    # 阶段2：解析安全策略规则
    # ------------------------------------------------------------------

    def _parse_rules(self, text: str) -> list[FlatRule]:
        """解析 set 格式的安全策略规则。"""
        # 先收集每条规则的属性
        rules_props: dict[str, dict[str, list[str]]] = defaultdict(
            lambda: defaultdict(list)
        )
        # 维护规则名称的出现顺序
        rule_order: list[str] = []
        seen_names: set[str] = set()

        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("set rulebase security rules "):
                continue

            tokens = _tokenize_line(line)
            # tokens: ['set', 'rulebase', 'security', 'rules', <name>, <prop>, ...]
            if len(tokens) < 6:
                continue

            rule_name = tokens[4]
            prop = tokens[5]

            if rule_name not in seen_names:
                rule_order.append(rule_name)
                seen_names.add(rule_name)

            # 收集值
            values = _collect_value(tokens, 6)

            # 某些属性需要覆盖而非追加（如 action, disabled, description）
            if prop in ("action", "disabled", "rule-type", "log-start",
                        "log-end", "log-setting", "group-tag"):
                rules_props[rule_name][prop] = values
            elif prop == "description":
                # description 可能在引号内，tokens[6] 就是完整描述
                if len(tokens) > 6:
                    # 用原始行提取引号内的描述（更可靠）
                    rules_props[rule_name]["description"] = values
                else:
                    rules_props[rule_name]["description"] = []
            elif prop == "profile-setting":
                # 忽略 profile-setting
                pass
            else:
                # from, to, source, destination, service, application,
                # source-user, category, source-hip, destination-hip
                # 追加值（支持多行 set 聚合同一属性）
                rules_props[rule_name][prop].extend(values)

        # 构建 FlatRule 列表
        rules: list[FlatRule] = []
        for seq, rule_name in enumerate(rule_order):
            props = rules_props[rule_name]
            rule = self._build_rule(rule_name, props, seq)
            if rule:
                rules.append(rule)

        return rules

    def _build_rule(
        self, name: str, props: dict[str, list[str]], seq: int
    ) -> FlatRule | None:
        """根据收集的属性构建单条 FlatRule。"""
        rule_warnings: list[Warning] = []

        # 启用/禁用
        disabled_vals = props.get("disabled", [])
        enabled = not (disabled_vals and disabled_vals[0].lower() == "yes")

        # 动作
        action_vals = props.get("action", ["deny"])
        action_text = action_vals[0].lower() if action_vals else "deny"
        if action_text == "allow":
            action: Literal["permit", "deny", "drop", "reject"] = "permit"
        elif action_text in ("deny", "drop", "reset-client", "reset-server", "reset-both"):
            action = "drop"
        else:
            action = "deny"

        # Zone
        src_zone_list = props.get("from", [])
        dst_zone_list = props.get("to", [])
        # 过滤 "any"
        src_zone_list = [z for z in src_zone_list if z.lower() != "any"]
        dst_zone_list = [z for z in dst_zone_list if z.lower() != "any"]

        # 源地址
        src_names = props.get("source", ["any"])
        if not src_names:
            src_names = ["any"]

        # 目的地址
        dst_names = props.get("destination", ["any"])
        if not dst_names:
            dst_names = ["any"]

        # 服务
        svc_names = props.get("service", ["any"])
        if not svc_names:
            svc_names = ["any"]

        # 应用
        app_names = props.get("application", ["any"])
        if not app_names:
            app_names = ["any"]

        # 展开地址
        src_ip = self._resolve_address_list(src_names)
        dst_ip = self._resolve_address_list(dst_names)

        # 展开服务（传入应用列表以支持 application-default 映射）
        services = self._resolve_service_list(svc_names, app_names)

        # 描述
        desc_vals = props.get("description", [])
        comment = " ".join(desc_vals) if desc_vals else ""

        # 日志：log-setting / log-start / log-end 任一存在即视为有日志
        log_enabled = bool(
            props.get("log-setting")
            or props.get("log-start")
            or props.get("log-end")
        )

        # 收集 object_store 警告
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
            src_zone="; ".join(src_zone_list) if src_zone_list else "",
            dst_zone="; ".join(dst_zone_list) if dst_zone_list else "",
            enabled=enabled,
            log_enabled=log_enabled,
            comment=comment,
            warnings=rule_warnings,
        )

    # ------------------------------------------------------------------
    # 辅助方法（与 XML 解析器共用逻辑）
    # ------------------------------------------------------------------

    def _parse_panos_port(self, port_text: str) -> PortRange:
        """
        解析 PAN-OS 端口字符串。

        格式：
          "any"           → PortRange.any()
          "80"            → PortRange(80, 80)
          "80-443"        → PortRange(80, 443)
          "80,443,8080"   → 仅取第一段
        """
        port_text = port_text.strip()
        if not port_text or port_text.lower() == "any":
            return PortRange.any()

        first = port_text.split(",")[0].strip()
        m = re.match(r"^(\d+)(?:-(\d+))?$", first)
        if m:
            lo = int(m.group(1))
            hi = int(m.group(2)) if m.group(2) else lo
            return PortRange(lo, hi)

        return PortRange.any()

    def _resolve_address_list(self, names: list[str]) -> list[AddressObject]:
        """展开地址名称列表。

        PAN-OS set 格式允许规则中直接使用 IP 字面量（裸 IP 或 CIDR）
        作为 source / destination，无需预先在 ``set address`` 中定义。
        此方法会自动检测并处理这类内联地址。
        """
        if not names or names == ["any"]:
            return [AddressObject(
                name="any", type="any", value="0.0.0.0/0",
                network=parse_ipv4_network("0.0.0.0/0"),
            )]
        result: list[AddressObject] = []
        seen: set[str] = set()
        for name in names:
            if name.lower() == "any":
                return [AddressObject(
                    name="any", type="any", value="0.0.0.0/0",
                    network=parse_ipv4_network("0.0.0.0/0"),
                )]
            # PAN-OS set 格式：规则中可以直接写 IP/CIDR 字面量
            if _IP_LITERAL_RE.match(name):
                # 裸 IP → /32
                value = name if "/" in name else f"{name}/32"
                net = parse_ipv4_network(value)
                if net is not None and value not in seen:
                    seen.add(value)
                    result.append(AddressObject(
                        name=name, type="subnet", value=value, network=net,
                    ))
                continue
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
