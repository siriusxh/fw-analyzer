"""
fw_analyzer/cli.py

CLI 入口（click）。

子命令：
  fw-analyzer parse    <file> [选项]   — 解析配置，输出规则表格
  fw-analyzer analyze  <file> [选项]   — 解析 + 全量分析，输出报告
  fw-analyzer batch    <dir>  [选项]   — 批量分析目录中所有可识别的配置文件
  fw-analyzer trace    <file> [选项]   — 访问需求命中分析
  fw-analyzer serve    [选项]          — 启动 REST API 服务器（需安装 [api] 额外依赖）

通用选项：
  --vendor   huawei/cisco-asa/paloalto/fortinet/auto（默认 auto）
  --config   自定义配置文件路径（TOML）
  --output   输出文件路径（默认 stdout）
  --format   csv / json / markdown / table（默认 table）
"""
from __future__ import annotations

import sys
from pathlib import Path

import click

from .parsers import get_parser, detect_vendor
from .config import load_config
from .analyzers.engine import AnalysisEngine
from .trace import TraceEngine, TraceQuery, load_trace_queries_from_csv
from .exporters.csv_exporter import CsvExporter
from .exporters.json_exporter import JsonExporter
from .exporters.markdown_exporter import MarkdownExporter
from .exporters.shadow_detail_exporter import ShadowDetailExporter


# ------------------------------------------------------------------
# 共用参数装饰器
# ------------------------------------------------------------------

def _common_options(f):
    """共用 CLI 选项：--vendor / --config / --output / --format。"""
    f = click.option(
        "--vendor", "-V",
        default="auto",
        show_default=True,
        type=click.Choice(
            ["auto", "huawei", "cisco-asa", "paloalto", "paloalto-set", "fortinet"],
            case_sensitive=False,
        ),
        help="厂商类型（auto 表示自动识别）。",
    )(f)
    f = click.option(
        "--config", "-c",
        default=None,
        metavar="FILE",
        help="自定义配置文件路径（TOML）。",
    )(f)
    f = click.option(
        "--output", "-o",
        default=None,
        metavar="FILE",
        help="输出文件路径（默认输出到 stdout）。",
    )(f)
    f = click.option(
        "--format", "-f", "fmt",
        default="table",
        show_default=True,
        type=click.Choice(["table", "csv", "json", "markdown"], case_sensitive=False),
        help="输出格式。",
    )(f)
    return f


# ------------------------------------------------------------------
# 工具函数
# ------------------------------------------------------------------

def _read_file(file_path: str) -> str:
    """读取文件内容，自动处理编码。"""
    path = Path(file_path)
    if not path.exists():
        raise click.ClickException(f"文件不存在: {file_path}")
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return path.read_text(encoding="gbk")


def _write_output(content: str, output: str | None) -> None:
    """输出到文件或 stdout。"""
    if output:
        Path(output).write_text(content, encoding="utf-8")
        click.echo(f"已保存到: {output}", err=True)
    else:
        click.echo(content)


def _detect_and_get_parser(content: str, vendor: str):
    """自动识别或使用指定厂商，返回 parser 实例。"""
    if vendor == "auto":
        vendor = detect_vendor(content)
        if not vendor:
            raise click.ClickException(
                "无法自动识别防火墙厂商。请使用 --vendor 明确指定。"
            )
        click.echo(f"[自动识别] 厂商: {vendor}", err=True)
    return get_parser(vendor)


def _analyze_single_file(
    file_path: str,
    content: str,
    vendor: str,
    cfg,
) -> tuple:
    """解析并分析单个配置文件，返回 (result, detected_vendor, content) 或抛出异常。

    Returns:
        (AnalysisResult, str, str) — 分析结果、检测到的厂商名、原始内容
    """
    if vendor == "auto":
        detected = detect_vendor(content)
        if not detected or detected == "unknown":
            raise click.ClickException(
                f"无法识别文件厂商: {file_path}"
            )
        actual_vendor = detected
    else:
        actual_vendor = vendor

    parser = get_parser(actual_vendor)
    parse_result = parser.parse(content, source_file=file_path)

    engine = AnalysisEngine(cfg)
    result = engine.analyze(parse_result)

    return result, actual_vendor, content


# ------------------------------------------------------------------
# 规则表格格式化（简单 Rich 表格，无 Rich 则降级 plain text）
# ------------------------------------------------------------------

def _format_rules_table(result) -> str:
    """将规则列表渲染为终端表格（使用 rich）。"""
    try:
        from rich.console import Console
        from rich.table import Table
        import io as _io

        table = Table(show_header=True, header_style="bold cyan", show_lines=False)
        table.add_column("#", style="dim", width=4)
        table.add_column("ID", max_width=18)
        table.add_column("名称", max_width=20)
        table.add_column("动作", width=7)
        table.add_column("源IP", max_width=22)
        table.add_column("目的IP", max_width=22)
        table.add_column("服务", max_width=18)
        table.add_column("启用", width=4)
        table.add_column("标签", max_width=30)

        for r in result.rules:
            action_style = "green" if r.action == "permit" else "red"
            tags = r.analysis_tags_str()
            tag_style = "yellow" if tags else ""
            table.add_row(
                str(r.seq + 1),
                r.raw_rule_id,
                r.rule_name,
                click.style(r.action, fg="green" if r.action == "permit" else "red"),
                r.src_ip_str(),
                r.dst_ip_str(),
                r.service_str(),
                "Y" if r.enabled else "N",
                tags,
                style=tag_style,
            )

        buf = _io.StringIO()
        console = Console(file=buf, width=160, highlight=False)
        console.print(table)
        return buf.getvalue()

    except ImportError:
        # 降级：plain text
        lines = [
            f"{'#':>4}  {'ID':<18}  {'名称':<20}  {'动作':<7}  {'源IP':<22}  {'目的IP':<22}  {'服务':<18}  {'启用':<4}  {'标签'}",
            "-" * 140,
        ]
        for r in result.rules:
            lines.append(
                f"{r.seq + 1:>4}  {r.raw_rule_id:<18}  {r.rule_name:<20}  "
                f"{r.action:<7}  {r.src_ip_str():<22}  {r.dst_ip_str():<22}  "
                f"{r.service_str():<18}  {'Y' if r.enabled else 'N':<4}  "
                f"{r.analysis_tags_str()}"
            )
        return "\n".join(lines)


def _format_trace_table(trace_results) -> str:
    """将 Trace 结果渲染为终端表格。"""
    try:
        from rich.console import Console
        from rich.table import Table
        import io as _io

        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("#", width=4)
        table.add_column("标签", max_width=14)
        table.add_column("源IP", max_width=18)
        table.add_column("目的IP", max_width=18)
        table.add_column("协议", width=6)
        table.add_column("目的端口", width=8)
        table.add_column("命中", width=4)
        table.add_column("规则", max_width=22)
        table.add_column("动作", width=8)
        table.add_column("说明", max_width=40)

        for i, tr in enumerate(trace_results, 1):
            q = tr.query
            hit = "Y" if tr.matched else "N"
            rule_info = (
                f"{tr.matched_rule.raw_rule_id} {tr.matched_rule.rule_name}"
                if tr.matched_rule else "-"
            )
            table.add_row(
                str(i),
                q.label or "-",
                q.src_ip,
                q.dst_ip,
                q.protocol,
                str(q.dst_port) if q.dst_port else "any",
                hit,
                rule_info,
                tr.action,
                tr.match_note or "",
                style="green" if tr.matched else "red",
            )

        buf = _io.StringIO()
        Console(file=buf, width=160, highlight=False).print(table)
        return buf.getvalue()

    except ImportError:
        lines = [
            f"{'#':>4}  {'标签':<12}  {'源IP':<18}  {'目的IP':<18}  {'协议':<6}  "
            f"{'目的端口':<8}  {'命中':<4}  {'规则':<22}  {'动作':<8}  {'说明'}",
            "-" * 120,
        ]
        for i, tr in enumerate(trace_results, 1):
            q = tr.query
            rule_info = (
                f"{tr.matched_rule.raw_rule_id} {tr.matched_rule.rule_name}"
                if tr.matched_rule else "-"
            )
            lines.append(
                f"{i:>4}  {(q.label or '-'):<12}  {q.src_ip:<18}  {q.dst_ip:<18}  "
                f"{q.protocol:<6}  {str(q.dst_port) if q.dst_port else 'any':<8}  "
                f"{'Y' if tr.matched else 'N':<4}  {rule_info:<22}  {tr.action:<8}  "
                f"{tr.match_note or ''}"
            )
        return "\n".join(lines)


# ------------------------------------------------------------------
# CLI 入口
# ------------------------------------------------------------------

@click.group()
@click.version_option(package_name="fw-analyzer")
def cli():
    """多厂商防火墙配置分析工具。

    支持华为 USG、Cisco ASA、Palo Alto PAN-OS、Fortinet FortiGate。

    常用示例：

    \b
      fw-analyzer parse   firewall.cfg
      fw-analyzer analyze firewall.cfg --format markdown -o report.md
      fw-analyzer batch   /path/to/configs/ -O /path/to/reports/
      fw-analyzer trace   firewall.cfg --src 10.0.0.1 --dst 8.8.8.8 --proto tcp --dport 443
      fw-analyzer serve   --port 8000
    """


# ------------------------------------------------------------------
# parse 子命令
# ------------------------------------------------------------------

@cli.command("parse")
@click.argument("file", type=click.Path(exists=True, readable=True))
@_common_options
def cmd_parse(file: str, vendor: str, config: str | None, output: str | None, fmt: str):
    """解析防火墙配置文件，输出规则 5 元组表格。

    FILE 为防火墙配置文件路径。
    """
    content = _read_file(file)
    parser = _detect_and_get_parser(content, vendor)

    try:
        parse_result = parser.parse(content, source_file=file)
    except Exception as e:
        raise click.ClickException(f"解析失败: {e}")

    # 打印解析警告到 stderr
    if parse_result.warnings:
        click.echo(f"\n[解析警告] 共 {len(parse_result.warnings)} 条：", err=True)
        for w in parse_result.warnings:
            click.echo(f"  [{w.severity.value.upper()}] {w.code}: {w.message}", err=True)

    click.echo(
        f"\n共解析 {parse_result.rule_count} 条规则"
        f"（启用 {parse_result.enabled_rule_count}，"
        f"禁用 {parse_result.rule_count - parse_result.enabled_rule_count}）",
        err=True,
    )

    # 构建一个轻量 AnalysisResult 用于导出（无分析标签）
    from .analyzers.engine import AnalysisResult
    analysis_result = AnalysisResult(
        rules=parse_result.rules,
        parse_warnings=parse_result.warnings,
        analysis_warnings=[],
        vendor=parse_result.vendor,
        source_file=parse_result.source_file,
    )

    if fmt == "table":
        out = _format_rules_table(analysis_result)
    elif fmt == "csv":
        out = CsvExporter().export(analysis_result)
    elif fmt == "json":
        out = JsonExporter().export(analysis_result)
    elif fmt == "markdown":
        out = MarkdownExporter().export(analysis_result)
    else:
        out = _format_rules_table(analysis_result)

    _write_output(out, output)


# ------------------------------------------------------------------
# analyze 子命令
# ------------------------------------------------------------------

@cli.command("analyze")
@click.argument("file", type=click.Path(exists=True, readable=True))
@_common_options
@click.option(
    "--shadow-detail", "shadow_detail",
    default=None,
    metavar="PREFIX",
    help="生成 Shadow 详细报告。指定输出文件名前缀，将生成 PREFIX.csv 和 PREFIX.md 两个文件。",
)
def cmd_analyze(file: str, vendor: str, config: str | None, output: str | None, fmt: str,
                shadow_detail: str | None):
    """解析并分析防火墙配置，检测影子规则、冗余规则、过宽规则和合规问题。

    FILE 为防火墙配置文件路径。
    """
    content = _read_file(file)
    parser = _detect_and_get_parser(content, vendor)

    try:
        parse_result = parser.parse(content, source_file=file)
    except Exception as e:
        raise click.ClickException(f"解析失败: {e}")

    cfg = load_config(config)
    engine = AnalysisEngine(cfg)

    try:
        result = engine.analyze(parse_result)
    except Exception as e:
        raise click.ClickException(f"分析失败: {e}")

    # 打印统计信息到 stderr
    click.echo(
        f"\n规则总数: {result.rule_count}  "
        f"问题规则: {result.issue_rule_count}  "
        f"信息性标记: {result.info_rule_count}  "
        f"合规告警: {len(result.analysis_warnings)}",
        err=True,
    )

    if fmt == "table":
        out = _format_rules_table(result)
    elif fmt == "csv":
        out = CsvExporter().export(result)
    elif fmt == "json":
        out = JsonExporter().export(result)
    elif fmt == "markdown":
        out = MarkdownExporter().export(result)
    else:
        out = _format_rules_table(result)

    _write_output(out, output)

    # Shadow Detail Report
    if shadow_detail:
        sd_exporter = ShadowDetailExporter(config_text=content)
        sd_csv = sd_exporter.export_csv(result)
        sd_md = sd_exporter.export_markdown(result)

        csv_path = f"{shadow_detail}.csv"
        md_path = f"{shadow_detail}.md"
        Path(csv_path).write_text(sd_csv, encoding="utf-8")
        Path(md_path).write_text(sd_md, encoding="utf-8")
        click.echo(
            f"\nShadow 详细报告已生成：\n  CSV: {csv_path}\n  Markdown: {md_path}",
            err=True,
        )


# ------------------------------------------------------------------
# batch 子命令
# ------------------------------------------------------------------

# batch 子命令专用的报告类型选项值
_REPORT_CHOICES = ["all", "summary", "csv", "markdown", "shadow-detail"]


@cli.command("batch")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, readable=True))
@click.option(
    "--output-dir", "-O",
    required=True,
    metavar="DIR",
    help="报告输出目录（不存在时自动创建）。",
)
@click.option(
    "--vendor", "-V",
    default="auto",
    show_default=True,
    type=click.Choice(
        ["auto", "huawei", "cisco-asa", "paloalto", "paloalto-set", "fortinet"],
        case_sensitive=False,
    ),
    help="厂商类型（auto 表示对每个文件自动识别）。",
)
@click.option(
    "--config", "-c",
    default=None,
    metavar="FILE",
    help="自定义配置文件路径（TOML）。",
)
@click.option(
    "--reports", "-r",
    default="all",
    show_default=True,
    type=click.Choice(_REPORT_CHOICES, case_sensitive=False),
    help="生成的报告类型：all=全部, summary=主报告CSV+MD, csv=仅CSV, markdown=仅MD, shadow-detail=仅影子详细报告。",
)
@click.option(
    "--recursive",
    is_flag=True,
    default=False,
    help="递归扫描子目录。",
)
def cmd_batch(
    directory: str,
    output_dir: str,
    vendor: str,
    config: str | None,
    reports: str,
    recursive: bool,
):
    """批量分析目录中所有可识别的防火墙配置文件。

    DIRECTORY 为包含配置文件的目录路径。

    自动识别目录中每个文件的厂商类型，对可识别的文件执行完整分析并输出报告。
    不可识别的文件会打印警告并跳过。

    输出文件以原配置文件名（去掉扩展名）为前缀，添加报告类型后缀：

    \b
      {stem}_analysis.csv           — 主分析报告 CSV
      {stem}_analysis.md            — 主分析报告 Markdown
      {stem}_shadow_detail.csv      — 影子规则详细报告 CSV
      {stem}_shadow_detail.md       — 影子规则详细报告 Markdown

    示例：

    \b
      fw-analyzer batch /path/to/configs/ -O /path/to/reports/
      fw-analyzer batch /path/to/configs/ -O ./reports --reports summary
      fw-analyzer batch /path/to/configs/ -O ./reports --recursive
    """
    # 确保输出目录存在
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # 收集文件列表
    src_dir = Path(directory)
    if recursive:
        files = sorted(p for p in src_dir.rglob("*") if p.is_file())
    else:
        files = sorted(p for p in src_dir.iterdir() if p.is_file())

    if not files:
        click.echo(f"目录为空: {directory}", err=True)
        return

    # 加载分析配置
    cfg = load_config(config)

    # 确定要生成的报告类型
    reports_lower = reports.lower()
    gen_csv = reports_lower in ("all", "summary", "csv")
    gen_md = reports_lower in ("all", "summary", "markdown")
    gen_shadow_csv = reports_lower in ("all", "shadow-detail")
    gen_shadow_md = reports_lower in ("all", "shadow-detail")

    click.echo(f"\n扫描目录: {directory}", err=True)
    click.echo(f"发现 {len(files)} 个文件，开始逐个分析…\n", err=True)

    processed = 0
    skipped = 0
    failed = 0

    for file_path in files:
        file_str = str(file_path)
        stem = file_path.stem
        rel = file_path.relative_to(src_dir) if recursive else file_path.name

        # 读取文件
        try:
            content = _read_file(file_str)
        except Exception as e:
            click.echo(f"  [跳过] {rel} — 读取失败: {e}", err=True)
            skipped += 1
            continue

        # 识别厂商
        if vendor == "auto":
            detected = detect_vendor(content)
            if not detected or detected == "unknown":
                click.echo(f"  [跳过] {rel} — 无法识别厂商", err=True)
                skipped += 1
                continue
            actual_vendor = detected
        else:
            actual_vendor = vendor

        # 解析 + 分析
        try:
            result, actual_vendor, content = _analyze_single_file(
                file_str, content, actual_vendor, cfg,
            )
        except Exception as e:
            click.echo(f"  [失败] {rel} ({actual_vendor}) — {e}", err=True)
            failed += 1
            continue

        # 生成报告
        file_count = 0

        if gen_csv:
            csv_out = CsvExporter().export(result)
            p = out_dir / f"{stem}_analysis.csv"
            p.write_text(csv_out, encoding="utf-8")
            file_count += 1

        if gen_md:
            md_out = MarkdownExporter().export(result)
            p = out_dir / f"{stem}_analysis.md"
            p.write_text(md_out, encoding="utf-8")
            file_count += 1

        if gen_shadow_csv or gen_shadow_md:
            sd_exporter = ShadowDetailExporter(config_text=content)
            if gen_shadow_csv:
                sd_csv = sd_exporter.export_csv(result)
                p = out_dir / f"{stem}_shadow_detail.csv"
                p.write_text(sd_csv, encoding="utf-8")
                file_count += 1
            if gen_shadow_md:
                sd_md = sd_exporter.export_markdown(result)
                p = out_dir / f"{stem}_shadow_detail.md"
                p.write_text(sd_md, encoding="utf-8")
                file_count += 1

        click.echo(
            f"  [完成] {rel} ({actual_vendor}) — "
            f"规则 {result.rule_count}, 问题 {result.issue_rule_count}, "
            f"生成 {file_count} 个报告",
            err=True,
        )
        processed += 1

    # 汇总
    click.echo(
        f"\n批量分析完成：处理 {processed} 个文件，跳过 {skipped} 个，失败 {failed} 个。"
        f"\n报告输出目录: {out_dir.resolve()}",
        err=True,
    )


# ------------------------------------------------------------------
# trace 子命令
# ------------------------------------------------------------------

@cli.command("trace")
@click.argument("file", type=click.Path(exists=True, readable=True))
@click.option("--src", required=False, default=None, help="源 IP（CIDR，如 10.0.0.1）。")
@click.option("--dst", required=False, default=None, help="目的 IP（CIDR，如 8.8.8.8）。")
@click.option("--proto", default="any", show_default=True, help="协议：tcp/udp/icmp/any。")
@click.option("--dport", default=0, show_default=True, type=int, help="目的端口（0=any）。")
@click.option("--sport", default=0, show_default=True, type=int, help="源端口（0=any）。")
@click.option(
    "--all-matches", "all_matches",
    is_flag=True, default=False,
    help="返回所有命中规则（默认只返回第一条）。",
)
@click.option(
    "--batch", "-b",
    default=None,
    metavar="CSV_FILE",
    help="从 CSV 文件批量读取查询（格式：src_ip,dst_ip,protocol,dst_port[,src_port][,label]）。",
)
@click.option("--vendor", "-V", default="auto",
              type=click.Choice(["auto", "huawei", "cisco-asa", "paloalto", "paloalto-set", "fortinet"],
                                case_sensitive=False),
              help="厂商类型。")
@click.option("--config", "-c", default=None, metavar="FILE", help="配置文件路径。")
@click.option("--output", "-o", default=None, metavar="FILE", help="输出文件路径。")
@click.option("--format", "-f", "fmt", default="table",
              type=click.Choice(["table", "csv", "json", "markdown"], case_sensitive=False),
              help="输出格式。")
def cmd_trace(
    file: str,
    src: str | None,
    dst: str | None,
    proto: str,
    dport: int,
    sport: int,
    all_matches: bool,
    batch: str | None,
    vendor: str,
    config: str | None,
    output: str | None,
    fmt: str,
):
    """对防火墙配置执行访问需求命中分析（Trace）。

    FILE 为防火墙配置文件路径。

    单条查询示例：

    \b
      fw-analyzer trace fw.cfg --src 10.0.0.1 --dst 8.8.8.8 --proto tcp --dport 443

    批量查询示例：

    \b
      fw-analyzer trace fw.cfg --batch queries.csv --format csv -o results.csv
    """
    content = _read_file(file)
    parser = _detect_and_get_parser(content, vendor)

    try:
        parse_result = parser.parse(content, source_file=file)
    except Exception as e:
        raise click.ClickException(f"解析失败: {e}")

    # 构建查询列表
    queries: list[TraceQuery] = []

    if batch:
        batch_content = _read_file(batch)
        queries = load_trace_queries_from_csv(batch_content)
        if not queries:
            raise click.ClickException(f"批量查询文件 {batch!r} 中未找到有效查询行。")
        click.echo(f"[批量查询] 从 {batch} 读取 {len(queries)} 条查询。", err=True)
    elif src and dst:
        queries = [TraceQuery(
            src_ip=src,
            dst_ip=dst,
            protocol=proto,
            dst_port=dport,
            src_port=sport,
        )]
    else:
        raise click.ClickException(
            "请指定 --src 和 --dst（单条查询），或使用 --batch <CSV文件>（批量查询）。"
        )

    trace_engine = TraceEngine(parse_result.rules)
    first_match_only = not all_matches
    results = trace_engine.trace_batch(queries, first_match_only=first_match_only)

    hit = sum(1 for r in results if r.matched)
    click.echo(f"\nTrace 完成：{len(results)} 条查询，命中 {hit} 条，未命中 {len(results) - hit} 条。", err=True)

    if fmt == "table":
        out = _format_trace_table(results)
    elif fmt == "csv":
        out = CsvExporter().export_trace(results)
    elif fmt == "json":
        out = JsonExporter().export_trace(results)
    elif fmt == "markdown":
        out = MarkdownExporter().export_trace(results)
    else:
        out = _format_trace_table(results)

    _write_output(out, output)


# ------------------------------------------------------------------
# serve 子命令
# ------------------------------------------------------------------

@cli.command("serve")
@click.option("--host", default="127.0.0.1", show_default=True, help="监听地址。")
@click.option("--port", default=8000, show_default=True, type=int, help="监听端口。")
@click.option("--reload", is_flag=True, default=False, help="开发模式热重载。")
def cmd_serve(host: str, port: int, reload: bool):
    """启动 REST API 服务器。

    需要先安装 API 额外依赖：

    \b
      pip install 'fw-analyzer[api]'
    """
    try:
        import uvicorn  # type: ignore[import]
    except ImportError:
        raise click.ClickException(
            "uvicorn 未安装。请运行: pip install 'fw-analyzer[api]'"
        )

    click.echo(f"启动 fw-analyzer API 服务: http://{host}:{port}")
    click.echo(f"API 文档: http://{host}:{port}/docs")

    uvicorn.run(
        "fw_analyzer.api.main:app",
        host=host,
        port=port,
        reload=reload,
    )


if __name__ == "__main__":
    cli()
