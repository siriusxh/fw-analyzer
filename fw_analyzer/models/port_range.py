"""
fw_analyzer/models/port_range.py

端口区间数据模型与运算。
支持单端口、范围端口、any（0-65535）的表示与包含/重叠判断。
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PortRange:
    """
    表示一个端口区间 [low, high]，low 和 high 均为闭区间端点。

    合法范围：0 <= low <= high <= 65535
    any 端口：PortRange(0, 65535)
    单端口：  PortRange(443, 443)
    """
    low: int
    high: int

    def __post_init__(self) -> None:
        if not (0 <= self.low <= 65535):
            raise ValueError(f"端口 low={self.low} 超出范围 [0, 65535]")
        if not (0 <= self.high <= 65535):
            raise ValueError(f"端口 high={self.high} 超出范围 [0, 65535]")
        if self.low > self.high:
            raise ValueError(f"端口区间非法: low={self.low} > high={self.high}")

    # ------------------------------------------------------------------
    # 工厂方法
    # ------------------------------------------------------------------

    @staticmethod
    def any() -> "PortRange":
        """返回表示任意端口的区间 [0, 65535]。"""
        return PortRange(0, 65535)

    @staticmethod
    def single(port: int) -> "PortRange":
        """返回单个端口的区间，如 PortRange.single(443) → [443, 443]。"""
        return PortRange(port, port)

    @staticmethod
    def from_string(s: str) -> "PortRange":
        """
        从字符串解析端口区间。

        支持格式：
          "any"           → PortRange(0, 65535)
          "0"             → PortRange(0, 0)
          "443"           → PortRange(443, 443)
          "8080-8443"     → PortRange(8080, 8443)
          "8080 to 8443"  → PortRange(8080, 8443)（华为格式）
          "eq 443"        → PortRange(443, 443)（Cisco 格式前缀，调用方应先剥离）
          "range 80 443"  → PortRange(80, 443)

        Raises:
            ValueError: 无法解析的格式
        """
        s = s.strip().lower()

        if s in ("any", "0-65535", "all"):
            return PortRange(0, 65535)

        # "range 80 443" 格式
        if s.startswith("range "):
            parts = s[6:].split()
            if len(parts) == 2:
                return PortRange(int(parts[0]), int(parts[1]))

        # "80-443" 或 "80 to 443" 格式
        if "-" in s:
            parts = s.split("-", 1)
            return PortRange(int(parts[0].strip()), int(parts[1].strip()))

        if " to " in s:
            parts = s.split(" to ", 1)
            return PortRange(int(parts[0].strip()), int(parts[1].strip()))

        # 单端口
        try:
            port = int(s)
            return PortRange(port, port)
        except ValueError:
            raise ValueError(f"无法解析端口区间字符串: {s!r}")

    # ------------------------------------------------------------------
    # 运算方法
    # ------------------------------------------------------------------

    def contains(self, other: "PortRange") -> bool:
        """
        判断 self 是否完全包含 other（self ⊇ other）。

        即 other 的所有端口都在 self 的范围内：
          self.low <= other.low  AND  other.high <= self.high
        """
        return self.low <= other.low and other.high <= self.high

    def overlaps(self, other: "PortRange") -> bool:
        """
        判断 self 与 other 是否有交集。

        两个区间有交集，当且仅当不满足"完全不相交"：
          NOT (self.high < other.low OR other.high < self.low)
        """
        return not (self.high < other.low or other.high < self.low)

    def is_any(self) -> bool:
        """判断是否为 any（覆盖全部端口 0-65535）。"""
        return self.low == 0 and self.high == 65535

    def is_single(self) -> bool:
        """判断是否为单端口。"""
        return self.low == self.high

    # ------------------------------------------------------------------
    # 显示方法
    # ------------------------------------------------------------------

    def __str__(self) -> str:
        if self.is_any():
            return "any"
        if self.is_single():
            return str(self.low)
        return f"{self.low}-{self.high}"

    def __repr__(self) -> str:
        return f"PortRange({self.low}, {self.high})"

    def to_dict(self) -> dict:
        return {"low": self.low, "high": self.high}
