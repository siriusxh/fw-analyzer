# fw-analyzer

多厂商防火墙配置分析工具，支持 5 元组提取、规则质量分析、访问需求命中分析（Trace）。

## 支持的厂商

| 厂商 | 格式 | 识别关键字 |
|------|------|-----------|
| 华为 USG | 文本 | `security-policy` / `acl number` |
| Cisco ASA | 文本 | `access-list` / `object-group` |
| Palo Alto PAN-OS | XML | `<config>` / `<security>` |
| Palo Alto PAN-OS | set 命令 | `set rulebase security rules` |
| Fortinet FortiGate | 层级文本 | `config firewall policy` |

## 安装

```bash
# 基础功能（CLI）
pip install fw-analyzer

# 包含 REST API
pip install 'fw-analyzer[api]'
```

## 快速上手

```bash
# 解析规则，输出终端表格
fw-analyzer parse firewall.cfg

# 分析规则质量，输出 Markdown 报告
fw-analyzer analyze firewall.cfg --format markdown -o report.md

# 检查访问需求是否命中
fw-analyzer trace firewall.cfg --src 10.0.0.1 --dst 8.8.8.8 --proto tcp --dport 443

# 批量 Trace 查询
fw-analyzer trace firewall.cfg --batch queries.csv --format csv -o results.csv

# 启动 REST API（需安装 [api] 依赖）
fw-analyzer serve --host 0.0.0.0 --port 8000
```

## 主要功能

### 规则解析（parse）

- 提取 5 元组：src_ip / dst_ip / protocol / src_port / dst_port
- 递归展开对象组（支持嵌套引用，超过 3 层触发警告）
- FQDN 类型地址保留原文，标记 `FQDN_SKIP`
- 非连续 Wildcard Mask 保留原文，标记 `NON_CONTIGUOUS_WILDCARD`
- PAN-OS `application-default` 服务自动映射：当 application 指定了具体应用（如 icmp/ping/dns/ntp 等），自动推断协议和端口

### 规则质量分析（analyze）

| 分析项 | 说明 |
|--------|------|
| 影子规则 | 前序规则完全覆盖后序规则（支持 zone/interface 感知），后序规则流量永远不会被匹配 |
| 冗余规则 | 5 元组签名完全相同的重复规则 |
| 过宽规则 | 允许高危端口宽泛访问（CRITICAL/HIGH/MEDIUM/LOW 四级） |
| 合规检查 | permit any any、明文协议、高危端口、缺少注释、禁用规则、无隐式拒绝、无工单号、无日志 |

### 合规检查标签

| 标签 | 性质 | 说明 |
|------|------|------|
| `COMPLIANCE:PERMIT_ANY_ANY` | 问题 | 存在 permit any any 规则 |
| `COMPLIANCE:CLEARTEXT` | 问题 | 允许明文协议（telnet/ftp/http 等） |
| `COMPLIANCE:HIGH_RISK_PORT` | 问题 | 允许高危端口 |
| `COMPLIANCE:NO_TICKET` | 问题 | 规则未关联 ITO 工单号 |
| `COMPLIANCE:NO_LOG` | 问题 | 规则未开启日志记录 |
| `COMPLIANCE:NO_COMMENT` | 信息 | 规则缺少注释描述 |
| `COMPLIANCE:DISABLED_RULES` | 信息 | 存在禁用的遗留规则 |

### ITO 工单号提取

自动从规则名称和注释中提取 ITO 工单号（支持 `ITO-1234`、`ITO 1234`、`ITO_1234` 等格式），统一归一化为 `ITO-NNNN` 格式。未关联工单号的启用规则标记 `COMPLIANCE:NO_TICKET`。

### 日志审计

检查所有启用规则的日志配置：
- **华为**：`policy logging` / `session logging` / `traffic logging`
- **Cisco ASA**：ACL 行尾 `log` 关键字
- **Fortinet**：`logtraffic` 为 `all` 或 `utm`
- **PAN-OS**：`log-setting` / `log-start` / `log-end` 属性

未开启日志的启用规则标记 `COMPLIANCE:NO_LOG`。

### 访问需求命中分析（trace）

- first-match 语义，支持 `--all-matches` 返回所有命中规则
- 支持单 IP（`/32`）和网段（`/N`）两种查询语义
- 支持批量 CSV 查询
- disabled 规则自动跳过，FQDN 对象标注说明

### 输出格式

- `table`：终端彩色表格（Rich 渲染，降级为纯文本）
- `csv`：UTF-8 with BOM，可直接用 Excel 打开
- `json`：结构化 JSON，适合程序对接
- `markdown`：适合文档生成和汇报（含标签分类统计表）

## 配置文件

支持 TOML 格式配置文件，自定义高危端口列表和合规检查开关：

```bash
# 复制示例配置
cp fw-analyzer.toml.example fw-analyzer.toml

# 或安装到用户主目录
mkdir -p ~/.fw-analyzer && cp fw-analyzer.toml.example ~/.fw-analyzer/config.toml
```

配置文件加载优先级：`--config 参数` > `./fw-analyzer.toml` > `~/.fw-analyzer/config.toml` > 内置默认值

## 文档

- [用户指南](docs/user-guide.md) — CLI 命令详解、分析标签说明、批量 Trace 用法
- [开发文档](docs/development.md) — 架构概览、数据模型、添加新解析器指南

## 开发

```bash
# 安装开发依赖
pip install -e '.[dev]'

# 运行测试
pytest

# 带覆盖率
pytest --cov=fw_analyzer --cov-report=term-missing
```

## 许可证

MIT
