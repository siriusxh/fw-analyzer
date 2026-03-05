"""
fw_analyzer/parsers/base.py

抽象解析器基类。

所有厂商解析器继承此类，实现：
  _parse_objects(text)  - 阶段1：解析所有对象定义，填充 object_store
  _parse_rules(text)    - 阶段2：解析规则，引用 object_store 展开对象

parse() 方法由基类统一调度，子类不应覆盖。
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from ..models.object_store import ObjectStore
from ..models.rule import FlatRule, ParseResult, Warning, WarningSeverity


class ParseError(Exception):
    """配置文件解析失败的异常。"""
    pass


class AbstractParser(ABC):
    """
    防火墙配置解析器抽象基类。

    子类实现示例：
        class HuaweiParser(AbstractParser):
            @property
            def vendor(self) -> str:
                return "huawei"

            def _parse_objects(self, text: str) -> None:
                # 解析 ip address-group、service-group 等
                ...

            def _parse_rules(self, text: str) -> list[FlatRule]:
                # 解析 firewall policy / security-policy rule 等
                ...
    """

    def __init__(self) -> None:
        self.object_store = ObjectStore()
        self._warnings: list[Warning] = []

    # ------------------------------------------------------------------
    # 抽象属性与方法
    # ------------------------------------------------------------------

    @property
    @abstractmethod
    def vendor(self) -> str:
        """厂商标识符，如 'huawei'、'cisco-asa'。"""
        ...

    @abstractmethod
    def _parse_objects(self, text: str) -> None:
        """
        阶段1：解析配置中的所有对象定义。

        应调用 self.object_store.add_address_object() 等方法注册对象。
        不返回值，结果存储在 self.object_store 中。
        """
        ...

    @abstractmethod
    def _parse_rules(self, text: str) -> list[FlatRule]:
        """
        阶段2：解析配置中的所有策略/ACL 规则。

        应调用 self.object_store.resolve_address() 等方法展开对象引用。
        返回 FlatRule 列表，seq 字段应反映规则在策略中的顺序。
        """
        ...

    # ------------------------------------------------------------------
    # 公共接口（子类不应覆盖）
    # ------------------------------------------------------------------

    def parse(self, text: str, source_file: str = "") -> ParseResult:
        """
        解析配置文本，返回 ParseResult。

        流程：
          1. 重置状态
          2. 调用 _parse_objects(text) 建立对象库
          3. 调用 _parse_rules(text) 解析规则
          4. 收集所有警告（对象库警告 + 规则解析警告）
          5. 返回 ParseResult
        """
        # 重置状态，支持同一实例多次调用
        self.object_store = ObjectStore()
        self._warnings = []

        try:
            self._parse_objects(text)
        except Exception as e:
            self._warn(
                f"对象解析阶段发生异常: {e}",
                code="PARSE_WARN",
                severity=WarningSeverity.ERROR,
            )

        rules: list[FlatRule] = []
        try:
            rules = self._parse_rules(text)
        except Exception as e:
            self._warn(
                f"规则解析阶段发生异常: {e}",
                code="PARSE_WARN",
                severity=WarningSeverity.ERROR,
            )

        # 收集所有警告
        store_warnings = [
            Warning.from_store_warning(sw)
            for sw in self.object_store.warnings
        ]
        all_warnings = store_warnings + self._warnings

        return ParseResult(
            rules=rules,
            warnings=all_warnings,
            vendor=self.vendor,
            source_file=source_file,
        )

    # ------------------------------------------------------------------
    # 子类辅助方法
    # ------------------------------------------------------------------

    def _warn(
        self,
        message: str,
        code: str = "PARSE_WARN",
        severity: WarningSeverity = WarningSeverity.WARN,
    ) -> None:
        """向全局警告列表追加一条警告。"""
        self._warnings.append(Warning(code=code, message=message, severity=severity))

    def _make_rule(self, **kwargs) -> FlatRule:
        """
        创建 FlatRule 的工厂方法，确保 vendor 字段自动填充。
        """
        kwargs.setdefault("vendor", self.vendor)
        return FlatRule(**kwargs)
