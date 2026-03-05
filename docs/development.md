# fw-analyzer 开发文档

## 目录

1. [项目结构](#项目结构)
2. [架构概览](#架构概览)
3. [核心数据模型](#核心数据模型)
4. [解析器模块](#解析器模块)
5. [分析器模块](#分析器模块)
6. [导出器模块](#导出器模块)
7. [Trace 模块](#trace-模块)
8. [API 模块](#api-模块)
9. [添加新厂商解析器](#添加新厂商解析器)
10. [测试](#测试)
11. [关键设计决策](#关键设计决策)
12. [已知限制](#已知限制)

---

## 项目结构

```
fw-analyzer/
├── pyproject.toml              # 项目元数据、依赖、构建配置
├── fw-analyzer.toml.example    # 配置文件模板
├── fw_analyzer/
│   ├── __init__.py             # 版本号
│   ├── cli.py                  # CLI 入口（click 子命令）
│   ├── config.py               # 配置加载（TOML）与默认高危端口
│   ├── trace.py                # 访问需求命中分析（TraceEngine）
│   ├── models/
│   │   ├── __init__.py
│   │   ├── ip_utils.py         # IPv4 地址解析与包含判断工具
│   │   ├── port_range.py       # PortRange 端口范围模型
│   │   ├── object_store.py     # AddressObject / ServiceObject / ObjectStore
│   │   └── rule.py             # FlatRule / ParseResult / Warning
│   ├── parsers/
│   │   ├── __init__.py         # get_parser() / detect_vendor()
│   │   ├── base.py             # AbstractParser 抽象基类
│   │   ├── detector.py         # 自动厂商识别
│   │   ├── huawei.py           # 华为 USG 解析器
│   │   ├── cisco_asa.py        # Cisco ASA 解析器
│   │   ├── palo_alto.py        # Palo Alto PAN-OS 解析器（XML）
│   │   └── fortinet.py         # Fortinet FortiGate 解析器
│   ├── analyzers/
│   │   ├── __init__.py
│   │   ├── engine.py           # AnalysisEngine / AnalysisResult
│   │   ├── shadow.py           # 影子规则检测
│   │   ├── redundancy.py       # 冗余规则检测
│   │   ├── overwidth.py        # 过宽规则检测
│   │   └── compliance.py       # 合规检查
│   ├── exporters/
│   │   ├── __init__.py
│   │   ├── csv_exporter.py     # CSV 导出（含 BOM）
│   │   ├── json_exporter.py    # JSON 导出
│   │   └── markdown_exporter.py# Markdown 导出
│   └── api/
│       ├── __init__.py
│       ├── main.py             # FastAPI app 实例
│       ├── schemas.py          # Pydantic 请求/响应模型
│       ├── dependencies.py     # FastAPI 依赖注入
│       └── routers/
│           ├── __init__.py
│           ├── parse.py        # POST /api/v1/parse
│           ├── analyze.py      # POST /api/v1/analyze
│           ├── trace.py        # POST /api/v1/trace
│           └── sessions.py     # 有状态会话接口
└── tests/
    ├── conftest.py             # pytest fixtures（加载示例配置）
    ├── test_parsers.py         # 各厂商解析器测试
    ├── test_analyzers.py       # 分析器测试
    ├── test_trace.py           # Trace 引擎测试
    ├── test_exporters.py       # 导出器测试
    └── fixtures/
        ├── huawei_simple.cfg
        ├── cisco_asa_simple.cfg
        ├── paloalto_simple.xml
        └── fortinet_simple.cfg
```

---

## 架构概览

整体数据流：

```
配置文件文本
    │
    ▼
[AbstractParser]  ──── 阶段1: _parse_objects() ──→ ObjectStore
    │                                                     │
    │             ──── 阶段2: _parse_rules()  ──←──── 对象展开
    │
    ▼
[ParseResult]
  rules: list[FlatRule]
  warnings: list[Warning]
    │
    ▼
[AnalysisEngine]
  ShadowAnalyzer   → 原地写入 rule.analysis_tags
  RedundancyAnalyzer
  OverwidthAnalyzer
  ComplianceAnalyzer → 返回全局告警
    │
    ▼
[AnalysisResult]
  rules: list[FlatRule]   (含 analysis_tags)
  parse_warnings / analysis_warnings
    │
    ├──→ [CsvExporter]      → str（CSV 文本）
    ├──→ [JsonExporter]     → str（JSON 文本）
    └──→ [MarkdownExporter] → str（Markdown 文本）
```

**核心原则：**

- **Exporters 无 IO**：所有导出器只返回字符串，不写文件。IO 操作统一在 `cli.py` 最外层完成。
- **规则原地修改**：分析器通过 `rule.analysis_tags.append(...)` 原地写入标签，不复制规则。
- **两阶段解析**：先建立对象库（`_parse_objects`），再解析规则（`_parse_rules`），保证前向引用正确解析。
- **仅处理 IPv4**：IPv6 地址对象直接跳过，不报错。

---

## 核心数据模型

### `FlatRule` (`models/rule.py`)

统一的防火墙规则表示。每条原始规则对应一个 `FlatRule`，对象组已递归展开为叶子节点列表。

```python
@dataclass
class FlatRule:
    vendor: str               # "huawei" / "cisco-asa" / "paloalto" / "fortinet"
    raw_rule_id: str          # 原始规则编号
    rule_name: str            # 可读名称
    seq: int                  # 规则序号（0-indexed）
    src_ip: list[AddressObject]
    dst_ip: list[AddressObject]
    services: list[ServiceObject]
    action: Literal["permit", "deny", "drop", "reject"]
    enabled: bool
    comment: str
    analysis_tags: list[str]  # 分析阶段写入
    warnings: list[Warning]   # 解析阶段写入
    # 可选位置信息
    src_zone: str
    dst_zone: str
    interface: str
    direction: str
```

**注意**：`src_ip`/`dst_ip` 字段名固定，不区分方向（`services` 中包含协议+端口信息）。

### `AddressObject` (`models/object_store.py`)

```python
@dataclass
class AddressObject:
    type: Literal["network", "host", "range", "fqdn", "any", "unknown"]
    value: str              # 原始字符串
    network: IPv4Network | None  # type=="network"/"host" 时有效
```

### `ServiceObject` (`models/object_store.py`)

```python
@dataclass
class ServiceObject:
    protocol: str        # "tcp"/"udp"/"icmp"/"any"/"tcp-udp"/"ip" 等
    src_port: PortRange
    dst_port: PortRange
    name: str            # 对象名（如 "HTTP"）
```

### `PortRange` (`models/port_range.py`)

```python
@dataclass
class PortRange:
    low: int   # 0–65535
    high: int  # low <= high

    @staticmethod
    def any() -> "PortRange": ...
    @staticmethod
    def single(port: int) -> "PortRange": ...

    def is_any(self) -> bool: ...
    def contains(self, other: "PortRange") -> bool: ...
    # 注意：contains 接受 PortRange 而不是 int
    # 检查单端口时：svc.dst_port.contains(PortRange.single(port))
```

### `ObjectStore` (`models/object_store.py`)

运行时对象注册表，供解析器阶段1建立、阶段2引用。

```python
class ObjectStore:
    def add_address_object(self, name: str, obj: AddressObject) -> None: ...
    def add_service_object(self, name: str, obj: ServiceObject) -> None: ...
    def resolve_address(self, name: str, visited: frozenset = frozenset()) -> list[AddressObject]: ...
    def resolve_service(self, name: str, visited: frozenset = frozenset()) -> list[ServiceObject]: ...

    # 循环引用检测：visited 集合按路径传递，不共享
    # e.g.: visited = visited | {name}  （每次创建新集合）
```

---

## 解析器模块

### 公共接口 (`parsers/__init__.py`)

```python
def get_parser(vendor: str) -> AbstractParser:
    """按厂商名返回对应解析器实例。"""

def detect_vendor(text: str) -> str | None:
    """自动识别配置文本的厂商类型，返回厂商名或 None。"""
```

### 抽象基类 (`parsers/base.py`)

所有解析器继承 `AbstractParser`，实现两个抽象方法：

```python
class AbstractParser(ABC):
    def parse(self, text: str, source_file: str = "") -> ParseResult:
        """公共入口，子类不应覆盖。"""

    @abstractmethod
    def _parse_objects(self, text: str) -> None:
        """阶段1：解析对象定义，注册到 self.object_store。"""

    @abstractmethod
    def _parse_rules(self, text: str) -> list[FlatRule]:
        """阶段2：解析规则，调用 self.object_store.resolve_* 展开对象。"""
```

辅助方法：

```python
self._warn(message, code="PARSE_WARN", severity=WarningSeverity.WARN)
self._make_rule(**kwargs)  # 自动填充 vendor 字段
```

### 各厂商解析器

| 厂商 | 文件 | 配置格式 | 特殊处理 |
|------|------|----------|---------|
| 华为 USG | `huawei.py` | 文本（key-value 缩进） | 支持旧版 ACL + 新版 security-policy；`mask` 在 address-group 中是子网掩码，在 ACL rule 中是 wildcard mask |
| Cisco ASA | `cisco_asa.py` | 文本（扁平层级） | `object`/`object-group` 展开；ACL 中 wildcard mask |
| Palo Alto | `palo_alto.py` | XML（`xml.etree.ElementTree`） | `address`/`address-group` 两阶段；zone 信息从 `from`/`to` 提取 |
| Fortinet | `fortinet.py` | 层级文本（`config`/`edit`/`next`/`end`） | `firewall address`/`service custom`/`policy` 块解析 |

---

## 分析器模块

### `AnalysisEngine` (`analyzers/engine.py`)

```python
engine = AnalysisEngine(config)  # config 可选，默认使用内置默认值
result = engine.analyze(parse_result)
# 按顺序执行：ShadowAnalyzer → RedundancyAnalyzer → OverwidthAnalyzer → ComplianceAnalyzer
```

### 影子规则 (`analyzers/shadow.py`)

**算法**：O(n²) 双重循环 + 剪枝

```
对于每对 (rule_i, rule_j)（i < j）：
  剪枝1：若 rule_i 或 rule_j 未启用，跳过
  剪枝2：若两者协议集合不相交，跳过
  剪枝3：若两者 IP 地址范围无重叠，跳过
  检查 rule_i 是否完全覆盖 rule_j：
    - rule_i.src_ip ⊇ rule_j.src_ip（存在 i 中某对象包含 j 中每个对象）
    - rule_i.dst_ip ⊇ rule_j.dst_ip
    - rule_i.services ⊇ rule_j.services（协议 + 端口范围）
  若覆盖：给 rule_j 打标签 SHADOW:SHADOWED_BY:seq=i
```

**覆盖语义**：全称量词——rule_i 必须覆盖 rule_j 中所有地址对象，不是任意一个。

### 冗余规则 (`analyzers/redundancy.py`)

**算法**：哈希签名 O(n)

```python
signature = (
    frozenset(src_ip strings),
    frozenset(dst_ip strings),
    frozenset(service strings),
    action,
)
# 相同签名的后出现规则打 REDUNDANT:DUP_OF:seq=N 标签
```

### 过宽规则 (`analyzers/overwidth.py`)

对每条启用的 `permit` 规则检查：

1. 源/目的地址是否包含 `any` 或 `0.0.0.0/0`
2. 服务端口范围是否覆盖全部 0-65535
3. 服务中是否包含高危端口（按 CRITICAL/HIGH/MEDIUM/LOW 分级）

### 合规检查 (`analyzers/compliance.py`)

规则级别标签写入 `rule.analysis_tags`，文件级别告警作为 `list[Warning]` 返回：

| 检查项 | 触发条件 | 级别 |
|--------|----------|------|
| PERMIT_ANY_ANY | src/dst/svc 均为 any | 规则级 |
| NO_COMMENT | permit 规则 comment 为空 | 规则级 |
| CLEARTEXT | permit 规则端口包含明文协议端口 | 规则级 |
| HIGH_RISK_PORT | permit 规则端口包含高危端口 | 规则级 |
| DISABLED_RULES | 规则 enabled=False | 规则级 |
| NO_IMPLICIT_DENY | 末尾 3 条 enabled 规则中无 deny all | 文件级 |

---

## 导出器模块

所有导出器实现相同接口，均为无 IO 纯函数：

```python
class CsvExporter:
    def export(self, result: AnalysisResult) -> str:
        """返回 CSV 文本（UTF-8 with BOM，Excel 兼容）。"""

    def export_trace(self, results: list[TraceResult]) -> str:
        """返回 Trace 结果 CSV 文本。"""

class JsonExporter:
    def export(self, result: AnalysisResult) -> str: ...
    def export_trace(self, results: list[TraceResult]) -> str: ...

class MarkdownExporter:
    def export(self, result: AnalysisResult) -> str: ...
    def export_trace(self, results: list[TraceResult]) -> str: ...
```

**CSV BOM**：`CsvExporter` 输出头部含 `\ufeff`（UTF-8 BOM），方便 Excel 双击直接打开中文列。

---

## Trace 模块

### `TraceEngine` (`trace.py`)

```python
engine = TraceEngine(rules)
result = engine.trace(query, first_match_only=True)
results = engine.trace_batch(queries, first_match_only=True)
```

### `TraceQuery`

```python
@dataclass
class TraceQuery:
    src_ip: str      # CIDR 格式，单 IP 自动补 /32
    dst_ip: str
    protocol: str    # "tcp"/"udp"/"icmp"/"any"
    dst_port: int    # 0 = any
    src_port: int    # 0 = any
    label: str       # 可选标签（批量查询时用）
```

### 匹配语义

```
单 IP (/32)：query ∈ rule_addr_obj（存在量词，被任一对象包含即命中）
网段 (/N<32)：rule_addr_obj ⊇ query（query 是某一对象的子网）

disabled 规则：跳过
FQDN 地址对象：跳过，在 match_note 中记录
空地址列表：等同于 any（全部命中）
空服务列表：等同于 any（全部命中）
```

### 批量 CSV 加载

```python
queries = load_trace_queries_from_csv(csv_text)
# CSV 列：src_ip, dst_ip, protocol, dst_port[, src_port][, label]
# 注释行（# 开头）和空行自动跳过
```

---

## API 模块

### 设计原则

- **可选依赖**：`fastapi`/`pydantic`/`uvicorn` 均为可选依赖（`pip install fw-analyzer[api]`），import 错误是预期行为，不影响核心功能。
- **骨架模式**：router 定义了接口契约，具体业务逻辑委托给现有 parsers/analyzers/trace。
- **两种使用模式**：
  - **无状态**：每次上传配置文件即时分析，返回结果
  - **有状态**：通过 `SessionStore` Protocol 抽象管理会话（内置 `InMemorySessionStore`）

### 接口布局

```
/api/v1/parse      POST  无状态解析
/api/v1/analyze    POST  无状态分析
/api/v1/trace      POST  无状态 Trace
/api/v1/sessions   POST  创建会话
/api/v1/sessions/{id}  GET/DELETE
```

### 启动方式

```python
# 程序内启动
from fw_analyzer.api.main import app
import uvicorn
uvicorn.run(app, host="0.0.0.0", port=8000)

# CLI 启动
fw-analyzer serve --host 0.0.0.0 --port 8000
```

---

## 添加新厂商解析器

以添加 "Check Point" 解析器为例：

### 1. 创建解析器文件

```python
# fw_analyzer/parsers/checkpoint.py
from __future__ import annotations
from .base import AbstractParser
from ..models.rule import FlatRule
from ..models.object_store import AddressObject, ServiceObject


class CheckPointParser(AbstractParser):

    @property
    def vendor(self) -> str:
        return "checkpoint"

    def _parse_objects(self, text: str) -> None:
        # 解析 network objects、service objects 等
        # 调用 self.object_store.add_address_object(name, obj)
        # 调用 self.object_store.add_service_object(name, obj)
        pass

    def _parse_rules(self, text: str) -> list[FlatRule]:
        rules = []
        # 解析规则，调用 self.object_store.resolve_address(name)
        # 使用 self._make_rule() 创建 FlatRule
        # 调用 self._warn() 记录解析警告
        return rules
```

### 2. 注册解析器

```python
# fw_analyzer/parsers/__init__.py

from .checkpoint import CheckPointParser

_PARSERS = {
    "huawei": HuaweiParser,
    "cisco-asa": CiscoAsaParser,
    "paloalto": PaloAltoParser,
    "fortinet": FortinetParser,
    "checkpoint": CheckPointParser,  # 添加此行
}
```

### 3. 添加自动识别

```python
# fw_analyzer/parsers/detector.py

_SIGNATURES = [
    # ... 现有签名 ...
    ("checkpoint", [r"^:", r"show version.*checkpoint"]),  # 示例
]
```

### 4. 添加测试夹具和测试

```python
# tests/fixtures/checkpoint_simple.cfg
# （添加示例配置文件）

# tests/conftest.py
@pytest.fixture
def checkpoint_cfg() -> str:
    return (FIXTURES_DIR / "checkpoint_simple.cfg").read_text(encoding="utf-8")

# tests/test_parsers.py
def test_checkpoint_parse(checkpoint_cfg):
    from fw_analyzer.parsers.checkpoint import CheckPointParser
    result = CheckPointParser().parse(checkpoint_cfg)
    assert result.vendor == "checkpoint"
    assert result.rule_count > 0
```

---

## 测试

### 运行测试

```bash
# 安装开发依赖
pip install -e '.[dev]'

# 运行全部测试
pytest

# 带覆盖率
pytest --cov=fw_analyzer --cov-report=term-missing

# 运行特定测试模块
pytest tests/test_parsers.py -v
pytest tests/test_trace.py -v
```

### 测试结构

| 文件 | 测试内容 |
|------|----------|
| `test_parsers.py` | 各厂商解析器：规则数量、动作、地址、服务、警告 |
| `test_analyzers.py` | 影子规则、冗余规则、过宽规则、合规检查 |
| `test_trace.py` | 单条查询、批量查询、FQDN 跳过、网段语义 |
| `test_exporters.py` | CSV/JSON/Markdown 导出格式验证 |

### 添加测试的规范

1. 每个新解析器必须有至少一个 fixture 文件（`tests/fixtures/`）
2. fixture 文件需覆盖：address-group、service-group、permit 规则、deny 规则、disabled 规则
3. 分析器测试通过手工构造 `FlatRule` 对象，不依赖解析器
4. 所有测试不得进行文件 IO（使用 fixture 字符串内容）

---

## 关键设计决策

### 仅处理 IPv4

IPv6 地址在解析阶段静默跳过，不产生 warning，不纳入分析。理由：大多数遗留防火墙配置主要为 IPv4，IPv6 混入会产生大量噪音。

### FQDN 不展开

FQDN 类型地址对象保留原文标记为 `FQDN_SKIP`，不进行 DNS 解析。理由：
- DNS 解析结果随时间变化，静态分析结果无法复现
- 批量分析时 DNS 查询会显著增加耗时
- 用户可在 Trace 报告中看到跳过的 FQDN 对象名称，手动判断

### 非连续 Wildcard Mask

Cisco ASA 和华为 ACL 中的 Wildcard Mask（如 `0.0.0.255`）允许非连续形式（如 `0.0.5.255`）。非连续形式无法用 `IPv4Network` 表示，fw-analyzer 保留原文并标记 `NON_CONTIGUOUS_WILDCARD` 警告。

### 对象组嵌套深度限制

`ObjectStore.resolve_*` 使用递归展开对象组，通过 `visited` 集合检测循环引用。嵌套超过 3 层时产生 `DEEP_NESTING` 警告（不终止解析）。每条解析路径使用独立的 `visited` 集合：

```python
# 正确做法（每次传入新集合）
visited = visited | {name}  # 创建新集合，不修改原集合
```

### 影子规则的覆盖语义

影子规则检测使用**全称量词**：rule_i 需要覆盖 rule_j 中**所有**地址对象，而不是任意一个。

Trace 命中使用**存在量词**：规则中**任意一个**地址对象包含查询 IP 即命中。

这两种语义不对称是有意设计：影子分析更保守（减少误报），Trace 语义与实际防火墙行为一致。

### PortRange.contains() 接受 PortRange 参数

```python
# 错误写法（会报 TypeError）
svc.dst_port.contains(443)

# 正确写法
svc.dst_port.contains(PortRange.single(443))
```

这是有意的类型一致性设计，避免隐式类型转换引发边界错误。

---

## 已知限制

1. **IPv6 不支持**：IPv6 地址对象全部跳过。
2. **FQDN 不展开**：FQDN 类型地址无法参与 IP 匹配分析。
3. **非连续 Wildcard Mask**：无法转换为 `IPv4Network`，仅保留原文。
4. **影子规则 O(n²) 复杂度**：规则数超过 1000 条时分析较慢（约 10 秒量级）。
5. **Cisco ASA 时间范围**：`time-range` 对象不影响规则启用状态判断。
6. **Fortinet VDOM**：当前解析器不区分 VDOM，所有策略合并处理。
7. **Palo Alto 安全档案**：不解析 Security Profile 绑定关系。
8. **REST API 为骨架**：`api/` 模块定义了接口契约，具体业务逻辑需根据 Web 框架需求完善。
