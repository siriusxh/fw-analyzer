# fw-analyzer 用户指南

## 目录

1. [安装](#安装)
2. [快速开始](#快速开始)
3. [CLI 子命令详解](#cli-子命令详解)
   - [parse — 规则解析](#parse--规则解析)
   - [analyze — 质量分析](#analyze--质量分析)
   - [batch — 批量分析](#batch--批量分析)
   - [trace — 访问需求命中分析](#trace--访问需求命中分析)
   - [serve — 启动 REST API](#serve--启动-rest-api)
4. [支持的输出格式](#支持的输出格式)
5. [配置文件](#配置文件)
6. [分析标签说明](#分析标签说明)
7. [批量 Trace 查询](#批量-trace-查询)
8. [REST API 使用](#rest-api-使用)
9. [常见问题](#常见问题)

---

## 安装

**要求**：Python 3.10+

```bash
# 基础安装（CLI 功能）
pip install fw-analyzer

# 包含 REST API 功能
pip install 'fw-analyzer[api]'

# 开发安装（含测试工具）
pip install -e '.[dev]'
```

验证安装：

```bash
fw-analyzer --version
```

---

## 快速开始

```bash
# 1. 解析华为 USG 配置，输出规则表格
fw-analyzer parse firewall.cfg

# 2. 分析规则质量，输出 Markdown 报告
fw-analyzer analyze firewall.cfg --format markdown -o report.md

# 3. 检查 10.0.0.1 能否访问 8.8.8.8:443/tcp
fw-analyzer trace firewall.cfg --src 10.0.0.1 --dst 8.8.8.8 --proto tcp --dport 443

# 4. 自动识别厂商（默认行为）
fw-analyzer parse unknown_fw.cfg --vendor auto

# 5. 分析规则质量，自动生成完整报告（CSV + Markdown + Shadow Detail）到目录
fw-analyzer analyze firewall.cfg -O ./reports/

# 6. 批量分析整个目录的配置文件
fw-analyzer batch /path/to/configs/ -O ./reports/
```

---

## CLI 子命令详解

### parse — 规则解析

解析防火墙配置文件，提取并展示所有规则的 5 元组（src_ip、dst_ip、protocol、src_port、dst_port）。

```
fw-analyzer parse <FILE> [选项]
```

**参数：**

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `FILE` | 防火墙配置文件路径 | 必填 |
| `--vendor / -V` | 厂商类型：`auto` / `huawei` / `cisco-asa` / `paloalto` / `fortinet` | `auto` |
| `--format / -f` | 输出格式：`table` / `csv` / `json` / `markdown` | `table` |
| `--output / -o` | 输出文件路径（不指定则输出到 stdout） | stdout |
| `--config / -c` | 自定义配置文件路径（TOML） | 自动查找 |

**示例：**

```bash
# 解析 Cisco ASA 配置，输出 CSV
fw-analyzer parse asa.cfg --vendor cisco-asa --format csv -o rules.csv

# 解析 Palo Alto 配置（XML）
fw-analyzer parse panorama.xml --vendor paloalto --format json -o rules.json

# 自动识别厂商，输出 Markdown
fw-analyzer parse firewall.cfg --format markdown
```

**输出字段说明：**

| 字段 | 说明 |
|------|------|
| `#` | 规则序号（从 1 开始） |
| `ID` | 规则原始 ID（如 ACL 编号、策略 ID） |
| `名称` | 规则名称（如无则为空） |
| `动作` | `permit` / `deny` / `drop` / `reject` |
| `源IP` | 源地址（多个用分号分隔；FQDN 标记为 `FQDN_SKIP`） |
| `目的IP` | 目的地址（同上） |
| `服务` | 协议+端口范围（如 `tcp:443`、`udp:53`、`any`） |
| `启用` | `Y`（启用）/ `N`（禁用） |
| `标签` | 分析标签（parse 子命令无分析标签） |

---

### analyze — 质量分析

在解析基础上，执行规则质量分析，检测影子规则、冗余规则、过宽规则和合规问题。

```
fw-analyzer analyze <FILE> [选项]
```

**参数：**

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `FILE` | 防火墙配置文件路径 | 必填 |
| `--vendor / -V` | 厂商类型：`auto` / `huawei` / `cisco-asa` / `paloalto` / `paloalto-set` / `fortinet` | `auto` |
| `--format / -f` | 输出格式：`table` / `csv` / `json` / `markdown` | `table` |
| `--output / -o` | 输出文件路径（不指定则输出到 stdout） | stdout |
| `--output-dir / -O` | 输出目录（自动命名模式），不可与 `-o` / `--shadow-detail` 同时使用 | — |
| `--shadow-detail` | 生成 Shadow 详细报告，指定文件名前缀（生成 `PREFIX.csv` 和 `PREFIX.md`） | — |
| `--config / -c` | 自定义配置文件路径（TOML） | 自动查找 |

支持两种输出模式：

**1) 手动模式（默认）** — 通过 `-f`/`-o` 控制单个输出文件：

```bash
# 分析华为防火墙，输出 Markdown 报告
fw-analyzer analyze huawei.cfg --format markdown -o report.md

# 使用自定义高危端口配置
fw-analyzer analyze fw.cfg --config myconfig.toml --format csv -o report.csv

# 额外生成 Shadow Detail 报告
fw-analyzer analyze fw.cfg -f csv -o report.csv --shadow-detail /path/to/shadow_prefix
```

**2) 自动命名模式（`-O`）** — 自动在指定目录下生成 4 个报告文件：

```bash
fw-analyzer analyze firewall.cfg -O ./reports/
```

自动生成以下文件（`{stem}` 为输入文件名去掉扩展名）：

| 文件 | 内容 |
|------|------|
| `{stem}_summary.csv` | 主分析报告（CSV，含 BOM） |
| `{stem}_summary.md` | 主分析报告（Markdown） |
| `{stem}_shadow_detail.csv` | 影子规则详细报告（CSV） |
| `{stem}_shadow_detail.md` | 影子规则详细报告（Markdown） |

**输出统计信息（stderr）：**

```
规则总数: 42  问题规则: 7  信息性标记: 3  合规告警: 2
```

---

### batch — 批量分析

批量分析目录中所有可识别的防火墙配置文件，自动识别厂商类型并逐个执行完整分析。

```
fw-analyzer batch <DIRECTORY> -O <OUTPUT_DIR> [选项]
```

**参数：**

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `DIRECTORY` | 包含配置文件的目录路径 | 必填 |
| `--output-dir / -O` | 报告输出目录（不存在时自动创建） | 必填 |
| `--vendor / -V` | 厂商类型（`auto` 表示对每个文件自动识别） | `auto` |
| `--reports / -r` | 生成的报告类型（见下表） | `all` |
| `--recursive` | 递归扫描子目录 | 关闭 |
| `--config / -c` | 自定义配置文件路径（TOML） | 自动查找 |

**`--reports` 选项值：**

| 值 | 生成内容 |
|----|----------|
| `all` | 全部 4 个报告文件（默认） |
| `summary` | 主报告 CSV + Markdown |
| `csv` | 仅主报告 CSV |
| `markdown` | 仅主报告 Markdown |
| `shadow-detail` | 仅影子详细报告 CSV + Markdown |

**输出文件命名规则：**

以原配置文件名（去掉扩展名）为 `{stem}`，生成以下文件：

- `{stem}_summary.csv` — 主分析报告 CSV
- `{stem}_summary.md` — 主分析报告 Markdown
- `{stem}_shadow_detail.csv` — 影子规则详细报告 CSV
- `{stem}_shadow_detail.md` — 影子规则详细报告 Markdown

**示例：**

```bash
# 分析目录中所有配置文件，生成全部报告
fw-analyzer batch /path/to/configs/ -O ./reports/

# 仅生成主报告（CSV + Markdown）
fw-analyzer batch /path/to/configs/ -O ./reports/ --reports summary

# 仅生成影子详细报告
fw-analyzer batch /path/to/configs/ -O ./reports/ --reports shadow-detail

# 递归扫描子目录
fw-analyzer batch /path/to/configs/ -O ./reports/ --recursive

# 指定厂商（跳过自动识别）
fw-analyzer batch /path/to/configs/ -O ./reports/ --vendor huawei
```

不可识别的文件会打印警告并跳过，不会终止整个批量流程。

---

### trace — 访问需求命中分析

给定源/目的 IP、协议、端口，在规则列表中按 **first-match** 语义查找命中规则。

```
fw-analyzer trace <FILE> [选项]
```

**参数：**

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `FILE` | 防火墙配置文件路径 | 必填 |
| `--src` | 源 IP（CIDR 格式，如 `10.0.0.1` 或 `10.0.0.0/24`） | — |
| `--dst` | 目的 IP（CIDR 格式） | — |
| `--proto` | 协议：`tcp` / `udp` / `icmp` / `any` | `any` |
| `--dport` | 目的端口（0 表示 any） | `0` |
| `--sport` | 源端口（0 表示 any） | `0` |
| `--all-matches` | 返回所有命中规则（默认只返回第一条） | 关闭 |
| `--batch / -b` | 从 CSV 文件批量读取查询 | — |
| `--vendor / -V` | 厂商类型 | `auto` |
| `--format / -f` | 输出格式 | `table` |
| `--output / -o` | 输出文件路径 | stdout |

**单条查询示例：**

```bash
# 检查 TCP 443 访问
fw-analyzer trace fw.cfg --src 10.0.0.1 --dst 8.8.8.8 --proto tcp --dport 443

# 检查整个子网的 UDP DNS 访问
fw-analyzer trace fw.cfg --src 192.168.1.0/24 --dst 8.8.8.8 --proto udp --dport 53

# 返回所有命中规则
fw-analyzer trace fw.cfg --src 10.0.0.1 --dst 0.0.0.0/0 --all-matches
```

**匹配语义说明：**

| 查询类型 | 命中条件 |
|----------|----------|
| 单 IP（`/32`） | 被规则中**任意**地址对象包含即命中 |
| 网段（如 `/24`） | 被规则中**某一**地址对象完全覆盖才命中 |
| disabled 规则 | 自动跳过 |
| FQDN 地址对象 | 跳过，在 `说明` 列记录 |

---

### serve — 启动 REST API

启动 FastAPI REST API 服务器（需安装 `[api]` 额外依赖）。

```
fw-analyzer serve [选项]
```

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--host` | 监听地址 | `127.0.0.1` |
| `--port` | 监听端口 | `8000` |
| `--reload` | 开发模式热重载 | 关闭 |

```bash
# 安装 API 依赖
pip install 'fw-analyzer[api]'

# 启动服务
fw-analyzer serve --host 0.0.0.0 --port 8080

# 访问 API 文档
# http://localhost:8080/docs
```

---

## 支持的输出格式

| 格式 | 说明 | 推荐场景 |
|------|------|----------|
| `table` | 终端彩色表格（Rich 渲染） | 交互式终端查看 |
| `csv` | CSV 文件（含 BOM，Excel 兼容） | 导入 Excel / 数据处理 |
| `json` | JSON 格式 | 程序对接 / 自动化 |
| `markdown` | Markdown 表格 | 文档生成 / 汇报 |

此外，`analyze` 和 `batch` 子命令还支持生成 **Shadow Detail（影子规则详细报告）**，包含被遮蔽规则和遮蔽规则的原始配置命令及引用对象定义，以 CSV 和 Markdown 两种格式输出。使用 `analyze -O` 或 `batch -O` 时自动生成，也可通过 `analyze --shadow-detail PREFIX` 手动指定。

---

## 配置文件

配置文件为 TOML 格式，用于自定义高危端口列表、过宽规则分级和合规检查开关。

**查找优先级（从高到低）：**

1. CLI `--config` 参数指定的路径
2. 当前目录 `./fw-analyzer.toml`
3. 用户主目录 `~/.fw-analyzer/config.toml`
4. 内置默认值

**快速配置：**

```bash
# 复制示例配置文件到当前目录
cp fw-analyzer.toml.example fw-analyzer.toml

# 或复制到用户主目录
mkdir -p ~/.fw-analyzer
cp fw-analyzer.toml.example ~/.fw-analyzer/config.toml
```

**配置文件结构：**

```toml
[high_risk_ports]
tcp = [20, 21, 23, 25, 53, 110, 139, 143, 389, 445, 512, 513, 514,
       1433, 1521, 3306, 3389, 4444, 5432, 5900, 6379, 10022, 27017]
udp = [53, 69, 137, 138, 161, 162, 514]

[overwide]
critical_ports = [22, 23, 139, 445, 3389, 4444, 10022]  # 远程控制类
high_ports     = [21, 25, 1433, 3306, 5432, 6379, 27017] # 数据库/服务
medium_ports   = [110, 143, 161, 162, 389, 512, 513, 514] # 邮件/目录
low_ports      = [20, 53, 69, 1521, 5900]                 # 常见但需关注

[compliance]
check_permit_any_any    = true    # 检查 permit any any
check_no_implicit_deny  = true    # 检查是否有末尾 deny all
check_cleartext         = true    # 检查明文协议
check_high_risk_ports   = true    # 检查高危端口
check_no_comment        = true    # 检查规则是否有注释
check_disabled_rules    = true    # 检查禁用规则
cleartext_ports = [21, 23, 25, 80, 110, 143, 161, 389, 514]
```

完整注释版示例见项目根目录 `fw-analyzer.toml.example`。

---

## 分析标签说明

`analyze` 子命令会在每条规则上附加分析标签，格式为 `分类:子类型[:detail]`。

### 影子规则（SHADOW）

| 标签 | 说明 |
|------|------|
| `SHADOW:SHADOWED_BY:seq=N` | 该规则被序号为 N 的规则完全覆盖（影子规则），流量永远不会到达此规则 |

**示例场景：** 规则 1 为 `permit any any`，规则 2 为 `permit 10.0.0.1 8.8.8.8 tcp 443`，则规则 2 被规则 1 遮蔽。

### 冗余规则（REDUNDANT）

| 标签 | 说明 |
|------|------|
| `REDUNDANT:DUP_OF:seq=N` | 该规则与序号为 N 的规则完全重复（相同 5 元组签名） |

### 过宽规则（OVERWIDE）

| 标签 | 说明 |
|------|------|
| `OVERWIDE:CRITICAL:port=P` | permit 规则允许 CRITICAL 级别高危端口 P 的宽泛访问 |
| `OVERWIDE:HIGH:port=P` | 同上，HIGH 级别 |
| `OVERWIDE:MEDIUM:port=P` | 同上，MEDIUM 级别 |
| `OVERWIDE:LOW:port=P` | 同上，LOW 级别 |
| `OVERWIDE:WILDCARD_SRC` | 源地址为 any/0.0.0.0 |
| `OVERWIDE:WILDCARD_DST` | 目的地址为 any/0.0.0.0 |
| `OVERWIDE:FULL_PORT_RANGE` | 端口范围覆盖全部 0-65535 |

### 合规（COMPLIANCE）

| 标签 | 说明 |
|------|------|
| `COMPLIANCE:PERMIT_ANY_ANY` | 规则为 permit any any（全通规则） |
| `COMPLIANCE:NO_COMMENT` | permit 规则缺少注释/描述 |
| `COMPLIANCE:CLEARTEXT:port=P` | permit 规则允许明文协议端口 P |
| `COMPLIANCE:HIGH_RISK_PORT:port=P` | permit 规则允许高危端口 P |
| `COMPLIANCE:DISABLED_RULES` | 规则已被禁用（可能是遗留规则） |
| `COMPLIANCE:NO_IMPLICIT_DENY`（全局） | 策略末尾无显式 deny all 规则 |

### 解析警告（不在规则标签中）

| 代码 | 说明 |
|------|------|
| `FQDN_SKIP` | 跳过 FQDN 类型地址，未展开为 IP |
| `NON_CONTIGUOUS_WILDCARD` | 非连续 Wildcard Mask，保留原文 |
| `DEEP_NESTING` | 对象组嵌套超过 3 层 |
| `UNKNOWN_OBJECT` | 引用了未定义的对象 |

---

## 批量 Trace 查询

使用 `--batch` 选项可以从 CSV 文件批量执行 Trace 查询。

**CSV 格式：**

```
src_ip,dst_ip,protocol,dst_port[,src_port][,label]
```

**示例文件（`queries.csv`）：**

```csv
10.0.0.1,8.8.8.8,tcp,443,,web-access
192.168.1.0/24,10.10.0.1,udp,53,,dns-query
10.0.0.5,172.16.0.1,tcp,3389,,rdp-check
10.0.0.0/24,0.0.0.0/0,any,0,,any-access
```

**执行批量查询：**

```bash
# 输出到终端
fw-analyzer trace fw.cfg --batch queries.csv

# 输出 CSV 结果（含 BOM，Excel 可直接打开）
fw-analyzer trace fw.cfg --batch queries.csv --format csv -o results.csv

# 输出 Markdown 报告
fw-analyzer trace fw.cfg --batch queries.csv --format markdown -o trace-report.md
```

**结果字段：**

| 字段 | 说明 |
|------|------|
| `标签` | 查询标签（来自 CSV `label` 列） |
| `源IP` | 查询源 IP |
| `目的IP` | 查询目的 IP |
| `协议` | 查询协议 |
| `目的端口` | 查询目的端口 |
| `命中` | `Y`（命中）/ `N`（未命中） |
| `规则` | 命中的规则 ID + 名称 |
| `动作` | `permit` / `deny` / `no-match` |
| `说明` | 跳过的 FQDN 对象等附加说明 |

---

## REST API 使用

> 需要先安装 API 依赖：`pip install 'fw-analyzer[api]'`

**启动服务：**

```bash
fw-analyzer serve --host 0.0.0.0 --port 8000
```

**主要接口：**

| 方法 | 路径 | 说明 |
|------|------|------|
| `POST` | `/api/v1/parse` | 上传配置文件，返回规则列表 |
| `POST` | `/api/v1/analyze` | 上传配置文件，返回分析报告 |
| `POST` | `/api/v1/trace` | 上传配置文件 + 查询条件，返回 Trace 结果 |
| `POST` | `/api/v1/sessions` | 创建有状态会话 |
| `GET` | `/api/v1/sessions/{id}` | 获取会话信息 |
| `DELETE` | `/api/v1/sessions/{id}` | 删除会话 |
| `GET` | `/docs` | Swagger UI 交互文档 |
| `GET` | `/redoc` | ReDoc 格式文档 |

详细接口契约见 `/docs`（Swagger UI）。

---

## 常见问题

**Q: 无法自动识别厂商类型怎么办？**

A: 使用 `--vendor` 手动指定：

```bash
fw-analyzer parse fw.cfg --vendor huawei
```

支持的厂商值：`huawei`、`cisco-asa`、`paloalto`、`fortinet`。

---

**Q: 华为配置解析结果为空？**

A: 华为 USG 支持两种策略格式：
- 旧版：`acl number`/`rule` 格式
- 新版：`security-policy`/`rule name` 格式

两种格式均支持，若仍为空，请检查配置文件编码（GBK 或 UTF-8）以及是否包含实际规则条目。

---

**Q: FQDN 类型地址为什么显示为 `FQDN_SKIP`？**

A: fw-analyzer 仅处理 IPv4 地址，FQDN（域名）类型的地址对象无法静态展开为 IP，因此保留原始域名并标记为 `FQDN_SKIP`。Trace 分析中涉及 FQDN 的对象会被跳过并在 `说明` 列注明。

---

**Q: 影子规则检测很慢？**

A: 影子规则检测为 O(n²) 复杂度，对于规则数超过 1000 条的大型策略会有延迟。已内置协议剪枝和 IP 重叠剪枝优化。如果配置过大，建议先过滤特定 ACL/策略后再分析。

---

**Q: 安装报错 `fastapi` 找不到？**

A: FastAPI 是可选依赖，仅 `serve` 子命令需要。安装方式：

```bash
pip install 'fw-analyzer[api]'
```

基础功能（`parse`/`analyze`/`batch`/`trace`）无需此依赖。
