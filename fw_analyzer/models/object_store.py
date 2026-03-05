"""
fw_analyzer/models/object_store.py

对象组存储与递归展开引擎。

支持华为 address-group/service-group、Cisco ASA object/object-group、
Palo Alto address/address-group/service/service-group、
Fortinet firewall address/addrgrp/service/custom/group。

核心特性：
- 两阶段使用：Parser 先调用 add_* 注册对象，再调用 resolve_* 展开
- 递归展开支持任意深度，超过 3 层触发警告
- 循环引用检测（visited set）
- FQDN 地址对象保留原文，不做 IP 转换
- 非连续 Wildcard 标记警告后保留原文
"""
from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import IPv4Network
from typing import Literal

from .ip_utils import parse_ipv4_network, NonContiguousWildcardError
from .port_range import PortRange


# ------------------------------------------------------------------
# 数据类：地址对象
# ------------------------------------------------------------------

@dataclass
class AddressObject:
    """
    统一的地址对象表示。

    type 枚举：
      host    - 单个主机 /32
      subnet  - 子网 CIDR
      range   - IP 范围（如 10.0.0.1-10.0.0.10，保留为字符串）
      fqdn    - 域名（如 api.example.com，不做 IP 解析）
      any     - 0.0.0.0/0
      unknown - 解析失败，保留原始字符串
    """
    name: str
    type: Literal["host", "subnet", "range", "fqdn", "any", "unknown"]
    value: str                          # 原始字符串表示
    network: IPv4Network | None = None  # type in (host/subnet/any) 时解析好的对象

    def __str__(self) -> str:
        if self.network is not None:
            return str(self.network)
        return self.value

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "type": self.type,
            "value": self.value,
            "network": str(self.network) if self.network else None,
        }


# ------------------------------------------------------------------
# 数据类：服务对象
# ------------------------------------------------------------------

@dataclass
class ServiceObject:
    """
    统一的服务对象表示（协议 + 源端口 + 目的端口）。
    """
    name: str
    protocol: str           # "tcp" / "udp" / "icmp" / "tcp-udp" / "any"
    src_port: PortRange
    dst_port: PortRange

    def __str__(self) -> str:
        proto = self.protocol
        if self.src_port.is_any() and self.dst_port.is_any():
            return proto
        if self.src_port.is_any():
            return f"{proto}/any/{self.dst_port}"
        return f"{proto}/{self.src_port}/{self.dst_port}"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "protocol": self.protocol,
            "src_port": self.src_port.to_dict(),
            "dst_port": self.dst_port.to_dict(),
        }


# ------------------------------------------------------------------
# 警告（在 rule.py 中有完整定义，此处为轻量版避免循环导入）
# ------------------------------------------------------------------

@dataclass
class StoreWarning:
    code: str
    message: str
    severity: str = "warn"  # "info" / "warn" / "error"


# ------------------------------------------------------------------
# 对象存储与展开引擎
# ------------------------------------------------------------------

class ObjectStore:
    """
    对象组存储与递归展开引擎。

    使用方式（Parser 调用）：
      store = ObjectStore()

      # 阶段1：注册所有对象定义
      store.add_address_object("web-server", "host", "10.0.0.1")
      store.add_address_group("grp-web", ["web-server", "db-server"])

      # 阶段2：在规则解析时展开
      addrs = store.resolve_address("grp-web")
      svcs  = store.resolve_service("HTTPS")
    """

    # 嵌套深度警告阈值
    NESTING_WARN_DEPTH = 3

    def __init__(self) -> None:
        # 地址对象：name → AddressObject（叶子节点）
        self._addr_objects: dict[str, AddressObject] = {}
        # 地址组：name → [member_name, ...]
        self._addr_groups: dict[str, list[str]] = {}
        # 服务对象：name → ServiceObject（叶子节点）
        self._svc_objects: dict[str, ServiceObject] = {}
        # 服务组：name → [member_name, ...]
        self._svc_groups: dict[str, list[str]] = {}
        # 展开过程产生的警告
        self.warnings: list[StoreWarning] = []

    # ------------------------------------------------------------------
    # 注册方法
    # ------------------------------------------------------------------

    def add_address_object(
        self,
        name: str,
        addr_type: str,
        value: str,
        mask: str | None = None,
    ) -> None:
        """
        注册一个地址对象。

        Args:
            name:      对象名称
            addr_type: "host" / "subnet" / "range" / "fqdn" / "any"
            value:     IP 字符串（host/subnet）、范围字符串（range）、域名（fqdn）、"any"
            mask:      可选的掩码（subnet mask 或 wildcard mask 字符串）
        """
        network: IPv4Network | None = None

        if addr_type == "any":
            network = parse_ipv4_network("0.0.0.0/0")
            value = "0.0.0.0/0"

        elif addr_type == "fqdn":
            # FQDN 保留原文，不解析
            pass

        elif addr_type == "range":
            # IP 范围（如 10.0.0.1-10.0.0.10）保留原文
            pass

        elif addr_type in ("host", "subnet"):
            try:
                network = parse_ipv4_network(value, mask)
                value = str(network)
                addr_type = "host" if network.prefixlen == 32 else "subnet"
            except NonContiguousWildcardError as e:
                self.warnings.append(StoreWarning(
                    code="NON_CONTIGUOUS_WILDCARD",
                    message=str(e),
                    severity="warn",
                ))
                addr_type = "unknown"
            except ValueError as e:
                self.warnings.append(StoreWarning(
                    code="PARSE_WARN",
                    message=f"地址对象 '{name}' 解析失败: {e}",
                    severity="warn",
                ))
                addr_type = "unknown"

        self._addr_objects[name] = AddressObject(
            name=name, type=addr_type, value=value, network=network  # type: ignore[arg-type]
        )

    def add_address_group(self, name: str, members: list[str]) -> None:
        """注册一个地址组（成员为其他对象或组的名称列表）。"""
        self._addr_groups[name] = list(members)

    def add_service_object(
        self,
        name: str,
        protocol: str,
        dst_port: PortRange | None = None,
        src_port: PortRange | None = None,
    ) -> None:
        """注册一个服务对象。"""
        self._svc_objects[name] = ServiceObject(
            name=name,
            protocol=protocol.lower(),
            src_port=src_port or PortRange.any(),
            dst_port=dst_port or PortRange.any(),
        )

    def add_service_group(self, name: str, members: list[str]) -> None:
        """注册一个服务组（成员为其他服务对象或服务组的名称列表）。"""
        self._svc_groups[name] = list(members)

    # ------------------------------------------------------------------
    # 展开方法
    # ------------------------------------------------------------------

    def resolve_address(
        self,
        name: str,
        depth: int = 0,
        visited: set[str] | None = None,
    ) -> list[AddressObject]:
        """
        递归展开地址对象或地址组，返回叶子 AddressObject 列表。

        Args:
            name:    对象/组名称，支持 "any" 特殊值
            depth:   当前递归深度（内部使用）
            visited: 已访问节点集合，用于循环引用检测（内部使用）

        Returns:
            展开后的 AddressObject 列表（去重）

        Side effects:
            超过 NESTING_WARN_DEPTH 时向 self.warnings 追加警告
        """
        if visited is None:
            visited = set()

        # 特殊关键字
        if name.lower() in ("any", "0.0.0.0/0"):
            return [AddressObject(
                name="any", type="any", value="0.0.0.0/0",
                network=parse_ipv4_network("0.0.0.0/0"),
            )]

        # 深度警告
        if depth > self.NESTING_WARN_DEPTH:
            self.warnings.append(StoreWarning(
                code="DEEP_NESTING",
                message=(
                    f"对象组 '{name}' 嵌套深度为 {depth} 层（超过建议上限 "
                    f"{self.NESTING_WARN_DEPTH} 层），建议优化配置结构。"
                ),
                severity="warn",
            ))

        # 循环引用检测
        if name in visited:
            self.warnings.append(StoreWarning(
                code="CIRCULAR_REFERENCE",
                message=f"对象组 '{name}' 存在循环引用，已跳过以防无限递归。",
                severity="error",
            ))
            return []

        visited = visited | {name}  # 不修改原集合，每条路径独立

        # 优先作为叶子对象查找
        if name in self._addr_objects:
            return [self._addr_objects[name]]

        # 作为组展开
        if name in self._addr_groups:
            result: list[AddressObject] = []
            for member in self._addr_groups[name]:
                result.extend(self.resolve_address(member, depth + 1, visited))
            return self._dedup_addresses(result)

        # 未找到：生成未知对象并警告
        self.warnings.append(StoreWarning(
            code="UNRESOLVED_OBJECT",
            message=f"地址对象/组 '{name}' 未找到定义，将保留名称原文。",
            severity="warn",
        ))
        return [AddressObject(name=name, type="unknown", value=name, network=None)]

    def resolve_service(
        self,
        name: str,
        depth: int = 0,
        visited: set[str] | None = None,
    ) -> list[ServiceObject]:
        """
        递归展开服务对象或服务组，返回叶子 ServiceObject 列表。

        支持 "any" 特殊值和协议名称直接作为服务名（如 "tcp"、"udp"、"icmp"）。
        """
        if visited is None:
            visited = set()

        name_lower = name.lower()

        # 特殊关键字：any 或直接是协议名
        if name_lower in ("any", "ip"):
            return [ServiceObject(
                name="any", protocol="any",
                src_port=PortRange.any(), dst_port=PortRange.any(),
            )]
        if name_lower in ("tcp", "udp", "icmp", "tcp-udp", "gre", "esp", "ah"):
            return [ServiceObject(
                name=name_lower, protocol=name_lower,
                src_port=PortRange.any(), dst_port=PortRange.any(),
            )]

        # 深度警告
        if depth > self.NESTING_WARN_DEPTH:
            self.warnings.append(StoreWarning(
                code="DEEP_NESTING",
                message=(
                    f"服务组 '{name}' 嵌套深度为 {depth} 层（超过建议上限 "
                    f"{self.NESTING_WARN_DEPTH} 层），建议优化配置结构。"
                ),
                severity="warn",
            ))

        # 循环引用检测
        if name in visited:
            self.warnings.append(StoreWarning(
                code="CIRCULAR_REFERENCE",
                message=f"服务组 '{name}' 存在循环引用，已跳过。",
                severity="error",
            ))
            return []

        visited = visited | {name}

        # 优先作为叶子对象查找
        if name in self._svc_objects:
            return [self._svc_objects[name]]

        # 作为组展开
        if name in self._svc_groups:
            result: list[ServiceObject] = []
            for member in self._svc_groups[name]:
                result.extend(self.resolve_service(member, depth + 1, visited))
            return result

        # 未找到
        self.warnings.append(StoreWarning(
            code="UNRESOLVED_OBJECT",
            message=f"服务对象/组 '{name}' 未找到定义，将作为 any 处理。",
            severity="warn",
        ))
        return [ServiceObject(
            name=name, protocol="any",
            src_port=PortRange.any(), dst_port=PortRange.any(),
        )]

    # ------------------------------------------------------------------
    # 辅助方法
    # ------------------------------------------------------------------

    def _dedup_addresses(self, addrs: list[AddressObject]) -> list[AddressObject]:
        """按 value 去重，保留顺序。"""
        seen: set[str] = set()
        result = []
        for a in addrs:
            if a.value not in seen:
                seen.add(a.value)
                result.append(a)
        return result

    def has_address(self, name: str) -> bool:
        return name in self._addr_objects or name in self._addr_groups

    def has_service(self, name: str) -> bool:
        return name in self._svc_objects or name in self._svc_groups

    def clear_warnings(self) -> None:
        self.warnings.clear()
