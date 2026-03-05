"""
fw_analyzer/models/ip_utils.py

IPv4 地址解析工具：统一处理 CIDR、Subnet Mask、Wildcard Mask 三种格式。
所有函数均为纯函数，无 IO 副作用。
"""
from __future__ import annotations

import ipaddress
from ipaddress import IPv4Network, IPv4Address


class NonContiguousWildcardError(ValueError):
    """非连续 Wildcard Mask，无法转换为单个 CIDR 网段。"""
    def __init__(self, ip: str, wildcard: str):
        self.ip = ip
        self.wildcard = wildcard
        super().__init__(
            f"非连续 Wildcard Mask: {ip} {wildcard}，无法转换为单个 CIDR，"
            "请检查配置或手动拆分为多条规则。"
        )


def is_wildcard_mask(mask: str) -> bool:
    """
    判断掩码字符串是 Wildcard Mask 还是 Subnet Mask。

    判断逻辑：
    - Subnet Mask 的首八位为 255 或 0（合法前缀如 255.x.x.x / 0.0.0.0）
    - Wildcard Mask 的首八位通常为 0（如 0.0.0.255）
    - 通过检测掩码整数值的位模式来区分：
      Subnet Mask 满足 (m & ~m+1) == 0（连续1后跟连续0）
      Wildcard Mask 是 Subnet Mask 的按位取反

    实际上更简单的判断：将掩码视为整数，若其按位取反后是合法子网掩码，则它是 wildcard。
    """
    try:
        mask_int = int(IPv4Address(mask))
    except ValueError:
        return False

    # 按位取反（32位）
    inverted = mask_int ^ 0xFFFFFFFF

    # 检测 inverted 是否是合法的连续子网掩码
    # 合法子网掩码：二进制为连续的1后跟连续的0，即 (inverted + 1) & inverted == 0
    # 同时 inverted 必须是 0xFFFFFFFF 开头（即原 mask 首位为0）
    if inverted == 0:
        # mask = 255.255.255.255，不是 wildcard
        return False
    if mask_int == 0:
        # mask = 0.0.0.0，可以是 wildcard（匹配任意）也可以是子网掩码，
        # 按 Wildcard 处理（更常见于 ACL 的 any）
        return True

    # 若原始掩码首字节 < 128，更可能是 wildcard（0.x.x.x）
    first_octet = mask_int >> 24
    if first_octet == 0:
        return True

    # 首字节 >= 128，更可能是 subnet mask（128.x.x.x ~ 255.x.x.x）
    return False


def is_contiguous_wildcard(wildcard: str) -> bool:
    """
    检测 Wildcard Mask 是否连续（可安全转换为 CIDR）。

    连续 Wildcard 的特征：其按位取反（得到子网掩码）满足：
      (subnet_mask_int + 1) & subnet_mask_int == 0
    即子网掩码是连续的1后跟连续的0。

    示例：
      0.0.0.255   → 取反 = 255.255.255.0  → 连续 ✓
      0.0.255.0   → 取反 = 255.255.0.255  → 不连续 ✗
      0.0.0.0     → 取反 = 255.255.255.255 → 连续 ✓（/0 即 any）
    """
    try:
        wc_int = int(IPv4Address(wildcard))
    except ValueError:
        return False

    subnet_int = wc_int ^ 0xFFFFFFFF
    # 合法子网掩码：(m + 1) & m == 0，且 m != 0 或 m == 全0
    return (subnet_int + 1) & subnet_int == 0


def wildcard_to_network(ip: str, wildcard: str) -> IPv4Network:
    """
    将 IP + Wildcard Mask 转换为 IPv4Network（CIDR）。

    步骤：
      1. 检测是否连续，不连续则抛出 NonContiguousWildcardError
      2. 将 wildcard 取反得到子网掩码
      3. 用 ipaddress 构造 IPv4Network（strict=False 允许主机位非零）

    Args:
        ip:       IP 地址字符串，如 "192.168.1.1"
        wildcard: Wildcard Mask 字符串，如 "0.0.0.255"

    Returns:
        IPv4Network，如 192.168.1.0/24

    Raises:
        NonContiguousWildcardError: 非连续 Wildcard
        ValueError: IP 或 mask 格式非法
    """
    if not is_contiguous_wildcard(wildcard):
        raise NonContiguousWildcardError(ip, wildcard)

    wc_int = int(IPv4Address(wildcard))
    subnet_int = wc_int ^ 0xFFFFFFFF
    subnet_mask = str(IPv4Address(subnet_int))
    return IPv4Network(f"{ip}/{subnet_mask}", strict=False)


def parse_ipv4_network(address: str, mask: str | None = None) -> IPv4Network:
    """
    统一入口：自动识别并解析 IPv4 网段，支持三种格式。

    调用方式：
      parse_ipv4_network("192.168.1.0/24")                   # CIDR
      parse_ipv4_network("192.168.1.0", "255.255.255.0")     # Subnet Mask
      parse_ipv4_network("192.168.1.0", "0.0.0.255")         # Wildcard Mask
      parse_ipv4_network("10.0.0.1")                          # 单 IP，作为 /32 处理
      parse_ipv4_network("any")                               # 返回 0.0.0.0/0
      parse_ipv4_network("host", "10.0.0.1")                  # Cisco host 关键字

    Returns:
        IPv4Network

    Raises:
        NonContiguousWildcardError: 非连续 Wildcard Mask
        ValueError: 无法解析的格式
    """
    # 处理特殊关键字
    if address.lower() in ("any", "0.0.0.0/0"):
        return IPv4Network("0.0.0.0/0")

    if address.lower() == "host":
        # "host 10.0.0.1" 格式，mask 参数是实际 IP
        if mask is None:
            raise ValueError("使用 'host' 关键字时必须提供 IP 地址作为 mask 参数")
        return IPv4Network(f"{mask}/32")

    if mask is None:
        # 尝试直接解析 CIDR 或单 IP
        try:
            return IPv4Network(address, strict=False)
        except ValueError:
            raise ValueError(f"无法解析 IPv4 地址/网段: {address!r}")

    # 有 mask 参数，判断是 Subnet Mask 还是 Wildcard Mask
    if is_wildcard_mask(mask):
        return wildcard_to_network(address, mask)
    else:
        # Subnet Mask
        try:
            return IPv4Network(f"{address}/{mask}", strict=False)
        except ValueError:
            raise ValueError(f"无法解析 IPv4 网段: {address} {mask}")


def network_contains(outer: IPv4Network, inner: IPv4Network) -> bool:
    """
    判断 outer 是否完全包含 inner（outer ⊇ inner）。

    即 inner 是 outer 的子网或等于 outer。
    封装 inner.subnet_of(outer)，统一异常处理。
    """
    try:
        return inner.subnet_of(outer)
    except TypeError:
        # IPv4 与 IPv6 混合时 subnet_of 会抛出 TypeError
        return False
