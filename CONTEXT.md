# 开发上下文（供 OpenCode 恢复会话使用）

## 项目目标

开发一个名为 `fw-analyzer` 的多厂商防火墙配置分析工具，目标是：
1. 解析防火墙配置文件，提取 5 元组（src_ip, dst_ip, protocol, src_port, dst_port）并输出表格
2. 识别防火墙规则质量问题（影子规则、冗余规则、过宽规则、安全合规）
3. 支持自定义高危端口配置文件（TOML）
4. 支持访问需求命中分析（trace）：给定源目 IP+端口，分析命中哪条规则及动作
5. 预留未来 Web 前端接入能力（FastAPI REST API 骨架）

---

## 厂商支持

- 华为 USG（文本格式，老版 ACL + 新版 security-policy）
- Cisco ASA（文本格式，object/object-group）
- Palo Alto PAN-OS（XML 格式）
- Fortinet FortiGate（层级文本格式）

---

## 关键技术决策

- **仅处理 IPv4**，不处理 IPv6
- **FQDN 类型规则**：保留原文，标记 `FQDN_SKIP`，不展开为 IP
- **对象组嵌套**：递归展开，超过 3 层触发 `DEEP_NESTING` 警告
- **输出粒度**：每条原始规则一行（不做笛卡尔积展开），对象组引用展开后用分号分隔在同格内
- **非连续 Wildcard Mask**：标记 `NON_CONTIGUOUS_WILDCARD` 警告，保留原文
- **不引入 Batfish**，用 `ipaddress` 标准库 + 自实现工具类
- **Exporters 无 IO 设计**：所有导出器只返回字符串/dict，不写文件，IO 操作统一在 `cli.py` 最外层完成
- **CLI 使用 `click`**（pyproject.toml 中已指定）
- **FastAPI/Pydantic 是可选依赖**，LSP 的 import 错误是预期行为

---

## 重要实现细节（避免踩坑）

- `PortRange.contains()` 接受 `PortRange` 参数而非 `int`，Trace 时需用 `PortRange.single(port)` 包装
- `StoreWarning` 在 `object_store.py` 中定义为轻量版，避免与 `rule.py` 的 `Warning` 循环导入
- `PaloAltoParser` 和 `FortinetParser` 使用基类两阶段调度（`_parse_objects` → `_parse_rules`）
- 影子规则的"覆盖"语义是**全称量词**，trace 命中语义是**存在量词**
- `ObjectStore` 中循环引用检测使用 `visited set`，每条路径独立（`visited = visited | {name}`）
- 华为配置中 `mask` 关键字在 `address-group` 块里是 subnet mask，在 `acl rule` 里是 wildcard mask
- CSV 导出器含 BOM（`\ufeff`）方便 Excel 直接打开
- `cli.py` 中 `parse` 子命令需要构建轻量 `AnalysisResult`（无分析标签）来复用导出器

---

## 当前完成状态（v0.1.0，已全部完成）

### 核心模块
- `fw_analyzer/models/` — ip_utils, port_range, object_store, rule
- `fw_analyzer/parsers/` — base, detector, huawei, cisco_asa, palo_alto, fortinet
- `fw_analyzer/analyzers/` — engine, shadow, redundancy, overwidth, compliance
- `fw_analyzer/exporters/` — csv_exporter, json_exporter, markdown_exporter
- `fw_analyzer/trace.py` — TraceEngine, TraceQuery, load_trace_queries_from_csv
- `fw_analyzer/config.py` — AnalyzerConfig, load_config (TOML)
- `fw_analyzer/cli.py` — click 子命令：parse / analyze / trace / serve
- `fw_analyzer/api/` — FastAPI 骨架（可选依赖）

### 测试
- `tests/fixtures/` — 四厂商示例配置
- `tests/test_parsers.py`, `test_analyzers.py`, `test_trace.py`, `test_exporters.py`

### 文档
- `README.md` — 项目首页
- `docs/user-guide.md` — 用户指南（中文）
- `docs/development.md` — 开发文档（中文）
- `fw-analyzer.toml.example` — 配置文件示例

---

## 可能的后续工作方向

- [ ] 运行测试套件，修复潜在 bug（`pip install -e '.[dev]' && pytest`）
- [ ] 补充更复杂的 fixture（对象组嵌套、FQDN、非连续 wildcard）
- [ ] 华为新版 security-policy 解析器完善
- [ ] 影子规则检测性能优化（超过 1000 条规则时）
- [ ] Web 前端（Vue/React）接入 FastAPI REST API
- [ ] 支持 Check Point / Juniper SRX 等更多厂商
- [ ] Excel (.xlsx) 导出格式
- [ ] CI/CD（GitHub Actions：lint + test + build）

---

## 开发环境快速启动

```bash
cd /path/to/fw-analyzer
pip install -e '.[dev]'
pytest                          # 运行测试
fw-analyzer --help              # 查看 CLI
fw-analyzer parse tests/fixtures/huawei_simple.cfg
```
