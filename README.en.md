# fw-analyzer

Multi-vendor firewall configuration analysis tool. Extracts 5-tuple rules, identifies quality issues (shadow, redundant, overwide), performs compliance checks, and supports access-request hit analysis (Trace).

## Supported Vendors

| Vendor | Format | Detection Keywords |
|--------|--------|--------------------|
| Huawei USG | Text | `security-policy` / `acl number` |
| Cisco ASA | Text | `access-list` / `object-group` |
| Palo Alto PAN-OS | XML | `<config>` / `<security>` |
| Palo Alto PAN-OS | set commands | `set rulebase security rules` |
| Fortinet FortiGate | Hierarchical text | `config firewall policy` |

## Installation

```bash
# Core CLI
pip install fw-analyzer

# With REST API support
pip install 'fw-analyzer[api]'
```

## Quick Start

```bash
# Parse rules, output terminal table
fw-analyzer parse firewall.cfg

# Analyze rule quality, output Markdown report
fw-analyzer analyze firewall.cfg --format markdown -o report.md

# Auto-generate full reports (CSV + Markdown + Shadow Detail) to a directory
fw-analyzer analyze firewall.cfg -O ./reports/

# Batch analyze all config files in a directory
fw-analyzer batch /path/to/configs/ -O ./reports/

# Check if an access request hits a rule
fw-analyzer trace firewall.cfg --src 10.0.0.1 --dst 8.8.8.8 --proto tcp --dport 443

# Batch trace queries
fw-analyzer trace firewall.cfg --batch queries.csv --format csv -o results.csv

# Start REST API (requires [api] extras)
fw-analyzer serve --host 0.0.0.0 --port 8000
```

## Features

### Rule Parsing (parse)

- Extracts 5-tuple: src_ip / dst_ip / protocol / src_port / dst_port
- Recursively expands object groups (nested references, warns beyond 3 levels)
- FQDN addresses preserved as-is, tagged `FQDN_SKIP`
- Non-contiguous wildcard masks preserved, tagged `NON_CONTIGUOUS_WILDCARD`
- PAN-OS `application-default` service auto-mapping: when specific applications are specified (e.g., icmp/ping/dns/ntp), protocol and port are inferred automatically

### Rule Quality Analysis (analyze)

| Analysis | Description |
|----------|-------------|
| Shadow rules | Earlier rule fully covers a later rule (zone/interface-aware); the later rule's traffic is never matched |
| Redundant rules | Duplicate rules with identical 5-tuple signatures |
| Overwide rules | Rules allowing broad access to high-risk ports (CRITICAL/HIGH/MEDIUM/LOW) |
| Compliance checks | permit any any, cleartext protocols, high-risk ports, missing comments, disabled rules, no implicit deny, missing ticket, missing logging |

Two output modes are supported:
- **Manual mode**: `fw-analyzer analyze config.txt -f csv -o report.csv` (optionally add `--shadow-detail PREFIX` for shadow detail reports)
- **Auto-naming mode**: `fw-analyzer analyze config.txt -O ./reports/` (automatically generates `_summary.csv`, `_summary.md`, `_shadow_detail.csv`, `_shadow_detail.md`)

### Compliance Tags

| Tag | Nature | Description |
|-----|--------|-------------|
| `COMPLIANCE:PERMIT_ANY_ANY` | Issue | Rule permits any source to any destination |
| `COMPLIANCE:CLEARTEXT` | Issue | Rule allows cleartext protocols (telnet/ftp/http) |
| `COMPLIANCE:HIGH_RISK_PORT` | Issue | Rule allows high-risk ports |
| `COMPLIANCE:NO_TICKET` | Issue | Rule has no associated ITO ticket number |
| `COMPLIANCE:NO_LOG` | Issue | Rule has logging disabled |
| `COMPLIANCE:NO_COMMENT` | Info | Rule lacks a description/comment |
| `COMPLIANCE:DISABLED_RULES` | Info | Legacy disabled rules exist |

### ITO Ticket Extraction

Automatically extracts ITO ticket numbers from rule names and comments (supports `ITO-1234`, `ITO 1234`, `ITO_1234`, etc.), normalized to `ITO-NNNN` format. Enabled rules without a ticket are tagged `COMPLIANCE:NO_TICKET`.

### Logging Audit

Checks logging configuration for all enabled rules:
- **Huawei**: `policy logging` / `session logging` / `traffic logging`
- **Cisco ASA**: Trailing `log` keyword in ACL lines
- **Fortinet**: `logtraffic` set to `all` or `utm`
- **PAN-OS**: `log-setting` / `log-start` / `log-end` attributes

Enabled rules without logging are tagged `COMPLIANCE:NO_LOG`.

### Access-Request Hit Analysis (trace)

- First-match semantics, `--all-matches` to return all matching rules
- Supports single IP (`/32`) and subnet (`/N`) query modes
- Supports batch CSV queries
- Disabled rules are automatically skipped; FQDN objects are annotated

### Batch Analysis (batch)

Batch analyze all recognizable config files in a directory, with automatic vendor detection and full analysis for each file.

```bash
# Analyze all config files in directory, generate all reports
fw-analyzer batch /path/to/configs/ -O ./reports/

# Generate only summary reports (CSV + Markdown)
fw-analyzer batch /path/to/configs/ -O ./reports/ --reports summary

# Recursively scan subdirectories
fw-analyzer batch /path/to/configs/ -O ./reports/ --recursive
```

Supports `--reports` to control report types (`all`/`summary`/`csv`/`markdown`/`shadow-detail`), `--vendor` to specify a uniform vendor, and `--recursive` for subdirectory scanning. Unrecognizable files are automatically skipped with a warning.

### Output Formats

- `table`: Colored terminal table (Rich rendering, falls back to plain text)
- `csv`: UTF-8 with BOM, can be opened directly in Excel
- `json`: Structured JSON for programmatic consumption
- `markdown`: Suitable for documentation and reporting (includes tag breakdown summary table)
- **Shadow Detail report**: Detailed shadow rule report (includes raw config commands and referenced object definitions), auto-generated via `analyze -O` / `batch -O`, or manually via `analyze --shadow-detail PREFIX`

## Configuration

Supports TOML configuration files for customizing high-risk port lists and compliance check toggles:

```bash
# Copy example config
cp fw-analyzer.toml.example fw-analyzer.toml

# Or install to user home directory
mkdir -p ~/.fw-analyzer && cp fw-analyzer.toml.example ~/.fw-analyzer/config.toml
```

Config file loading priority: `--config flag` > `./fw-analyzer.toml` > `~/.fw-analyzer/config.toml` > built-in defaults

## Documentation

- [User Guide](docs/user-guide.md) — CLI command reference, analysis tag descriptions, batch Trace usage (Chinese)
- [Development Guide](docs/development.md) — Architecture overview, data models, adding new parsers (Chinese)

## Development

```bash
# Install dev dependencies
pip install -e '.[dev]'

# Run tests
pytest

# With coverage
pytest --cov=fw_analyzer --cov-report=term-missing
```

## License

MIT
