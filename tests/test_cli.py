"""
tests/test_cli.py

CLI 核心路径 + 错误处理测试。
使用 click 的 CliRunner 进行测试。

注意：Click 8.x 的 CliRunner 不支持 mix_stderr 参数，stderr 会混入 output。
因此：
  - 检查 stderr 消息时，使用 result.output（包含 stdout+stderr）
  - 解析 JSON 时，需要先定位 JSON 起始位置跳过 stderr 前缀
"""
from __future__ import annotations

import json
import os
import pytest
from pathlib import Path
from click.testing import CliRunner

from fw_analyzer.cli import cli

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _extract_json(output: str) -> object:
    """从 CliRunner 混合输出中提取 JSON 对象。

    Click 8.x 的 CliRunner 将 stderr 混入 output，
    需要找到 JSON 的起始位置（'{' 或 '['）再解析。
    """
    for i, ch in enumerate(output):
        if ch in ('{', '['):
            return json.loads(output[i:])
    raise ValueError(f"未在输出中找到 JSON 内容: {output[:200]!r}")


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def huawei_path():
    return str(FIXTURES_DIR / "huawei_simple.cfg")


@pytest.fixture
def cisco_path():
    return str(FIXTURES_DIR / "cisco_asa_simple.cfg")


@pytest.fixture
def paloalto_path():
    return str(FIXTURES_DIR / "paloalto_simple.xml")


@pytest.fixture
def fortinet_path():
    return str(FIXTURES_DIR / "fortinet_simple.cfg")


# ======================================================================
# TestCliParse
# ======================================================================


class TestCliParse:
    """parse 子命令测试。"""

    def test_parse_table(self, runner, huawei_path):
        """默认 table 格式输出。"""
        result = runner.invoke(cli, ["parse", huawei_path, "--vendor", "huawei"])
        assert result.exit_code == 0
        assert "共解析" in result.output

    def test_parse_csv(self, runner, huawei_path):
        """CSV 格式输出。"""
        result = runner.invoke(cli, ["parse", huawei_path, "--vendor", "huawei", "-f", "csv"])
        assert result.exit_code == 0
        # CSV 应包含逗号分隔的数据
        lines = result.output.strip().split("\n")
        assert len(lines) >= 2  # 表头 + 至少1条规则

    def test_parse_json(self, runner, huawei_path):
        """JSON 格式输出可解析。"""
        result = runner.invoke(cli, ["parse", huawei_path, "--vendor", "huawei", "-f", "json"])
        assert result.exit_code == 0
        data = _extract_json(result.output)
        assert "rules" in data

    def test_parse_markdown(self, runner, huawei_path):
        """Markdown 格式输出。"""
        result = runner.invoke(cli, ["parse", huawei_path, "--vendor", "huawei", "-f", "markdown"])
        assert result.exit_code == 0
        assert "|" in result.output  # Markdown 表格

    def test_parse_vendor_override(self, runner, cisco_path):
        """显式指定 vendor。"""
        result = runner.invoke(cli, ["parse", cisco_path, "--vendor", "cisco-asa"])
        assert result.exit_code == 0
        assert "共解析" in result.output

    def test_parse_output_to_file(self, runner, huawei_path, tmp_path):
        """输出到文件。"""
        out_file = str(tmp_path / "output.csv")
        result = runner.invoke(
            cli, ["parse", huawei_path, "--vendor", "huawei", "-f", "csv", "-o", out_file]
        )
        assert result.exit_code == 0
        assert Path(out_file).exists()
        content = Path(out_file).read_text(encoding="utf-8")
        assert len(content) > 0

    def test_parse_nonexistent_file(self, runner):
        """不存在文件报错。"""
        result = runner.invoke(cli, ["parse", "/tmp/nonexistent_fw_file.cfg"])
        assert result.exit_code != 0

    def test_parse_invalid_vendor(self, runner, huawei_path):
        """无效 vendor 报错。"""
        result = runner.invoke(cli, ["parse", huawei_path, "--vendor", "invalid-vendor"])
        assert result.exit_code != 0


# ======================================================================
# TestCliAnalyze
# ======================================================================


class TestCliAnalyze:
    """analyze 子命令测试。"""

    def test_analyze_table(self, runner, huawei_path):
        result = runner.invoke(cli, ["analyze", huawei_path, "--vendor", "huawei"])
        assert result.exit_code == 0
        assert "规则总数" in result.output

    def test_analyze_csv(self, runner, huawei_path):
        result = runner.invoke(cli, ["analyze", huawei_path, "--vendor", "huawei", "-f", "csv"])
        assert result.exit_code == 0

    def test_analyze_json(self, runner, huawei_path):
        result = runner.invoke(cli, ["analyze", huawei_path, "--vendor", "huawei", "-f", "json"])
        assert result.exit_code == 0
        data = _extract_json(result.output)
        assert "rules" in data

    def test_analyze_markdown(self, runner, huawei_path):
        result = runner.invoke(
            cli, ["analyze", huawei_path, "--vendor", "huawei", "-f", "markdown"]
        )
        assert result.exit_code == 0
        assert "|" in result.output

    def test_analyze_with_config(self, runner, huawei_path, tmp_path):
        """自定义 config 文件。"""
        toml = tmp_path / "test.toml"
        toml.write_text('[high_risk_ports]\ntcp = [22, 23]\n', encoding="utf-8")
        result = runner.invoke(
            cli, ["analyze", huawei_path, "--vendor", "huawei", "-c", str(toml)]
        )
        assert result.exit_code == 0

    def test_analyze_stderr_summary(self, runner, huawei_path):
        """output 中包含统计摘要（Click 8.x 将 stderr 混入 output）。"""
        result = runner.invoke(cli, ["analyze", huawei_path, "--vendor", "huawei"])
        assert "规则总数" in result.output
        assert "问题规则" in result.output

    def test_analyze_nonexistent_file(self, runner):
        result = runner.invoke(cli, ["analyze", "/tmp/nonexistent_fw_file.cfg"])
        assert result.exit_code != 0


# ======================================================================
# TestCliTrace
# ======================================================================


class TestCliTrace:
    """trace 子命令测试。"""

    def test_trace_single_hit(self, runner, huawei_path):
        """单条查询命中。"""
        result = runner.invoke(cli, [
            "trace", huawei_path, "--vendor", "huawei",
            "--src", "192.168.1.1", "--dst", "8.8.8.8",
            "--proto", "tcp", "--dport", "80",
        ])
        assert result.exit_code == 0
        assert "Trace 完成" in result.output

    def test_trace_single_miss(self, runner, huawei_path):
        """单条查询未命中（deny-all 兜底之前的特殊条件）。"""
        result = runner.invoke(cli, [
            "trace", huawei_path, "--vendor", "huawei",
            "--src", "192.168.1.1", "--dst", "8.8.8.8",
            "--proto", "tcp", "--dport", "80",
        ])
        assert result.exit_code == 0

    def test_trace_all_matches(self, runner, huawei_path):
        """--all-matches 选项。"""
        result = runner.invoke(cli, [
            "trace", huawei_path, "--vendor", "huawei",
            "--src", "192.168.1.1", "--dst", "8.8.8.8",
            "--proto", "tcp", "--dport", "80",
            "--all-matches",
        ])
        assert result.exit_code == 0

    def test_trace_csv_format(self, runner, huawei_path):
        result = runner.invoke(cli, [
            "trace", huawei_path, "--vendor", "huawei",
            "--src", "192.168.1.1", "--dst", "8.8.8.8",
            "--proto", "tcp", "--dport", "80",
            "-f", "csv",
        ])
        assert result.exit_code == 0

    def test_trace_json_format(self, runner, huawei_path):
        result = runner.invoke(cli, [
            "trace", huawei_path, "--vendor", "huawei",
            "--src", "192.168.1.1", "--dst", "8.8.8.8",
            "--proto", "tcp", "--dport", "80",
            "-f", "json",
        ])
        assert result.exit_code == 0
        data = _extract_json(result.output)
        assert isinstance(data, (list, dict))

    def test_trace_markdown_format(self, runner, huawei_path):
        result = runner.invoke(cli, [
            "trace", huawei_path, "--vendor", "huawei",
            "--src", "192.168.1.1", "--dst", "8.8.8.8",
            "--proto", "tcp", "--dport", "80",
            "-f", "markdown",
        ])
        assert result.exit_code == 0

    def test_trace_batch_csv(self, runner, huawei_path, tmp_path):
        """批量 CSV 查询。"""
        batch_file = tmp_path / "queries.csv"
        batch_file.write_text(
            "src_ip,dst_ip,protocol,dst_port\n"
            "192.168.1.1,8.8.8.8,tcp,80\n"
            "10.0.0.1,172.16.0.1,tcp,443\n",
            encoding="utf-8",
        )
        result = runner.invoke(cli, [
            "trace", huawei_path, "--vendor", "huawei",
            "--batch", str(batch_file),
        ])
        assert result.exit_code == 0
        assert "批量查询" in result.output

    def test_trace_missing_params(self, runner, huawei_path):
        """缺少 --src/--dst 且无 --batch 报错。"""
        result = runner.invoke(cli, [
            "trace", huawei_path, "--vendor", "huawei",
        ])
        assert result.exit_code != 0

    def test_trace_nonexistent_file(self, runner):
        result = runner.invoke(cli, [
            "trace", "/tmp/nonexistent_fw_file.cfg",
            "--src", "10.0.0.1", "--dst", "10.0.0.2",
        ])
        assert result.exit_code != 0

    def test_trace_nonexistent_batch(self, runner, huawei_path):
        result = runner.invoke(cli, [
            "trace", huawei_path, "--vendor", "huawei",
            "--batch", "/tmp/nonexistent_batch.csv",
        ])
        assert result.exit_code != 0


# ======================================================================
# TestCliServe
# ======================================================================


class TestCliServe:
    """serve 子命令（轻量测试）。"""

    def test_serve_help(self, runner):
        """--help 正常输出。"""
        result = runner.invoke(cli, ["serve", "--help"])
        assert result.exit_code == 0
        assert "REST API" in result.output or "uvicorn" in result.output


# ======================================================================
# TestCliGeneral
# ======================================================================


class TestCliGeneral:
    """通用 CLI 测试。"""

    def test_version(self, runner):
        """--version 正常输出。"""
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0


# ======================================================================
# TestCliAutoDetect — 自动识别厂商
# ======================================================================


class TestCliAutoDetect:
    """测试 vendor=auto 自动识别功能。"""

    def test_auto_detect_huawei(self, runner):
        path = str(FIXTURES_DIR / "huawei_simple.cfg")
        result = runner.invoke(cli, ["parse", path])
        assert result.exit_code == 0
        assert "自动识别" in result.output
        assert "共解析" in result.output

    def test_auto_detect_cisco(self, runner):
        path = str(FIXTURES_DIR / "cisco_asa_simple.cfg")
        result = runner.invoke(cli, ["parse", path])
        assert result.exit_code == 0
        assert "自动识别" in result.output

    def test_auto_detect_paloalto(self, runner):
        path = str(FIXTURES_DIR / "paloalto_simple.xml")
        result = runner.invoke(cli, ["parse", path])
        assert result.exit_code == 0
        assert "自动识别" in result.output

    def test_auto_detect_fortinet(self, runner):
        path = str(FIXTURES_DIR / "fortinet_simple.cfg")
        result = runner.invoke(cli, ["parse", path])
        assert result.exit_code == 0
        assert "自动识别" in result.output


# ======================================================================
# TestCliComplexFixtures — 复杂 fixture 全链路测试
# ======================================================================


class TestCliComplexFixtures:
    """使用复杂 fixture 测试 CLI 的 parse / analyze / trace 全链路。"""

    # --- parse 子命令 ---

    def test_parse_huawei_complex(self, runner):
        path = str(FIXTURES_DIR / "huawei_complex.cfg")
        result = runner.invoke(cli, ["parse", path, "--vendor", "huawei", "-f", "csv"])
        assert result.exit_code == 0
        # CSV 输出应有多行（表头 + 规则行）
        lines = [l for l in result.output.strip().split("\n") if "," in l]
        assert len(lines) >= 2  # 表头 + 至少1条规则

    def test_parse_cisco_complex(self, runner):
        path = str(FIXTURES_DIR / "cisco_asa_complex.cfg")
        result = runner.invoke(cli, ["parse", path, "--vendor", "cisco-asa", "-f", "csv"])
        assert result.exit_code == 0
        lines = [l for l in result.output.strip().split("\n") if "," in l]
        assert len(lines) >= 2

    def test_parse_paloalto_complex(self, runner):
        path = str(FIXTURES_DIR / "paloalto_complex.xml")
        result = runner.invoke(cli, ["parse", path, "--vendor", "paloalto", "-f", "json"])
        assert result.exit_code == 0
        data = _extract_json(result.output)
        assert len(data["rules"]) > 0

    def test_parse_fortinet_complex(self, runner):
        path = str(FIXTURES_DIR / "fortinet_complex.cfg")
        result = runner.invoke(cli, ["parse", path, "--vendor", "fortinet", "-f", "json"])
        assert result.exit_code == 0
        data = _extract_json(result.output)
        assert len(data["rules"]) > 0

    # --- analyze 子命令（应检出 DEEP_NESTING 等警告）---

    def test_analyze_cisco_complex_has_warnings(self, runner):
        """Cisco ASA 复杂 fixture 应触发 DEEP_NESTING 等解析警告。"""
        path = str(FIXTURES_DIR / "cisco_asa_complex.cfg")
        result = runner.invoke(cli, ["analyze", path, "--vendor", "cisco-asa", "-f", "json"])
        assert result.exit_code == 0
        data = _extract_json(result.output)
        # 应有 parse_warnings 包含 DEEP_NESTING
        warnings = data.get("parse_warnings", [])
        assert any("DEEP_NESTING" in w.get("code", "") for w in warnings)

    def test_analyze_paloalto_complex_has_tagged_rules(self, runner):
        """PAN-OS 复杂 fixture 分析后有标记规则。"""
        path = str(FIXTURES_DIR / "paloalto_complex.xml")
        result = runner.invoke(cli, ["analyze", path, "--vendor", "paloalto"])
        assert result.exit_code == 0
        assert "问题规则" in result.output or "信息性标记" in result.output

    def test_analyze_fortinet_complex_json(self, runner):
        """Fortinet 复杂 fixture 分析结果 JSON 可解析。"""
        path = str(FIXTURES_DIR / "fortinet_complex.cfg")
        result = runner.invoke(cli, ["analyze", path, "--vendor", "fortinet", "-f", "json"])
        assert result.exit_code == 0
        data = _extract_json(result.output)
        assert "rules" in data
        assert "parse_warnings" in data

    # --- trace 子命令（用复杂 fixture）---

    def test_trace_huawei_complex(self, runner):
        path = str(FIXTURES_DIR / "huawei_complex.cfg")
        result = runner.invoke(cli, [
            "trace", path, "--vendor", "huawei",
            "--src", "10.1.1.1", "--dst", "172.16.0.1",
            "--proto", "tcp", "--dport", "80",
        ])
        assert result.exit_code == 0
        assert "Trace 完成" in result.output

    def test_trace_cisco_complex_json(self, runner):
        path = str(FIXTURES_DIR / "cisco_asa_complex.cfg")
        result = runner.invoke(cli, [
            "trace", path, "--vendor", "cisco-asa",
            "--src", "10.1.1.1", "--dst", "192.168.1.1",
            "--proto", "tcp", "--dport", "443",
            "-f", "json",
        ])
        assert result.exit_code == 0
        data = _extract_json(result.output)
        assert isinstance(data, (list, dict))


# ======================================================================
# TestCliEdgeCases — 边界情况
# ======================================================================


class TestCliEdgeCases:
    """CLI 边界情况测试。"""

    def test_trace_with_sport(self, runner):
        """--sport 参数正常传递。"""
        path = str(FIXTURES_DIR / "huawei_simple.cfg")
        result = runner.invoke(cli, [
            "trace", path, "--vendor", "huawei",
            "--src", "192.168.1.1", "--dst", "8.8.8.8",
            "--proto", "tcp", "--dport", "80", "--sport", "12345",
        ])
        assert result.exit_code == 0
        assert "Trace 完成" in result.output

    def test_trace_with_sport_json(self, runner):
        """--sport 参数在 JSON 输出中体现。"""
        path = str(FIXTURES_DIR / "huawei_simple.cfg")
        result = runner.invoke(cli, [
            "trace", path, "--vendor", "huawei",
            "--src", "192.168.1.1", "--dst", "8.8.8.8",
            "--proto", "tcp", "--dport", "80", "--sport", "12345",
            "-f", "json",
        ])
        assert result.exit_code == 0
        data = _extract_json(result.output)
        assert isinstance(data, (list, dict))

    def test_gbk_encoding_file(self, runner, tmp_path):
        """GBK 编码的配置文件能正常读取。"""
        # 创建一个简单的 GBK 编码华为配置
        cfg = (
            '#\n'
            'sysname USG6000\n'
            '#\n'
            'acl number 3001\n'
            ' rule 0 permit tcp source 192.168.1.0 0.0.0.255 destination any '
            'destination-port eq 80\n'
            ' rule 1 deny ip\n'
            '#\n'
        )
        gbk_file = tmp_path / "huawei_gbk.cfg"
        gbk_file.write_bytes(cfg.encode("gbk"))
        result = runner.invoke(cli, ["parse", str(gbk_file), "--vendor", "huawei"])
        assert result.exit_code == 0
        assert "共解析" in result.output

    def test_parse_all_formats_cisco_complex(self, runner):
        """所有输出格式 (csv/json/markdown/table) 都能正常工作。"""
        path = str(FIXTURES_DIR / "cisco_asa_complex.cfg")
        for fmt in ["csv", "json", "markdown", "table"]:
            result = runner.invoke(cli, [
                "parse", path, "--vendor", "cisco-asa", "-f", fmt
            ])
            assert result.exit_code == 0, f"Format {fmt} failed"

    def test_analyze_output_to_file(self, runner, tmp_path):
        """analyze 输出到文件。"""
        path = str(FIXTURES_DIR / "huawei_complex.cfg")
        out_file = str(tmp_path / "report.json")
        result = runner.invoke(cli, [
            "analyze", path, "--vendor", "huawei", "-f", "json", "-o", out_file
        ])
        assert result.exit_code == 0
        assert Path(out_file).exists()
        data = json.loads(Path(out_file).read_text(encoding="utf-8"))
        assert "rules" in data

    def test_trace_batch_with_complex_fixture(self, runner, tmp_path):
        """批量查询复杂 fixture。"""
        path = str(FIXTURES_DIR / "cisco_asa_complex.cfg")
        batch_file = tmp_path / "queries.csv"
        batch_file.write_text(
            "src_ip,dst_ip,protocol,dst_port\n"
            "10.1.1.1,192.168.1.1,tcp,443\n"
            "172.16.0.1,10.0.0.1,udp,53\n",
            encoding="utf-8",
        )
        result = runner.invoke(cli, [
            "trace", path, "--vendor", "cisco-asa",
            "--batch", str(batch_file), "-f", "csv",
        ])
        assert result.exit_code == 0
        assert "批量查询" in result.output


# ======================================================================
# TestCliBatch
# ======================================================================


class TestCliBatch:
    """batch 子命令测试。"""

    @pytest.fixture
    def batch_dir(self, tmp_path):
        """创建包含多厂商配置文件的临时目录。"""
        d = tmp_path / "configs"
        d.mkdir()
        # 复制简单 fixture 文件到临时目录
        import shutil
        for name in ("huawei_simple.cfg", "cisco_asa_simple.cfg", "fortinet_simple.cfg"):
            src = FIXTURES_DIR / name
            if src.exists():
                shutil.copy(src, d / name)
        return d

    @pytest.fixture
    def out_dir(self, tmp_path):
        return tmp_path / "reports"

    def test_batch_basic(self, runner, batch_dir, out_dir):
        """基本批量处理：多厂商配置文件全部分析，生成所有报告。"""
        result = runner.invoke(cli, [
            "batch", str(batch_dir), "-O", str(out_dir),
        ])
        assert result.exit_code == 0
        assert "批量分析完成" in result.output
        assert "处理 3 个文件" in result.output
        # 每个文件应生成 4 个报告
        report_files = list(out_dir.iterdir())
        assert len(report_files) == 12  # 3 files × 4 reports

    def test_batch_output_naming(self, runner, batch_dir, out_dir):
        """验证输出文件命名：{stem}_analysis.csv 等。"""
        result = runner.invoke(cli, [
            "batch", str(batch_dir), "-O", str(out_dir),
        ])
        assert result.exit_code == 0
        # 检查华为文件的输出命名
        assert (out_dir / "huawei_simple_analysis.csv").exists()
        assert (out_dir / "huawei_simple_analysis.md").exists()
        assert (out_dir / "huawei_simple_shadow_detail.csv").exists()
        assert (out_dir / "huawei_simple_shadow_detail.md").exists()
        # 检查 Cisco 文件的输出命名
        assert (out_dir / "cisco_asa_simple_analysis.csv").exists()
        assert (out_dir / "cisco_asa_simple_analysis.md").exists()

    def test_batch_skip_unrecognized(self, runner, batch_dir, out_dir):
        """混入不可识别的文件，应跳过并打印警告。"""
        # 添加一个无法识别的文本文件
        (batch_dir / "readme.txt").write_text("This is not a firewall config.", encoding="utf-8")
        # 添加一个空文件
        (batch_dir / "empty.log").write_text("", encoding="utf-8")
        result = runner.invoke(cli, [
            "batch", str(batch_dir), "-O", str(out_dir),
        ])
        assert result.exit_code == 0
        assert "跳过" in result.output
        assert "处理 3 个文件" in result.output
        assert "跳过 2 个" in result.output

    def test_batch_empty_dir(self, runner, tmp_path):
        """空目录不报错。"""
        empty = tmp_path / "empty"
        empty.mkdir()
        out = tmp_path / "out"
        result = runner.invoke(cli, [
            "batch", str(empty), "-O", str(out),
        ])
        assert result.exit_code == 0
        assert "目录为空" in result.output

    def test_batch_no_recognized_files(self, runner, tmp_path):
        """目录中只有不可识别文件。"""
        d = tmp_path / "junk"
        d.mkdir()
        (d / "notes.txt").write_text("hello world", encoding="utf-8")
        (d / "data.bin").write_bytes(b"\x00\x01\x02\x03")
        out = tmp_path / "out"
        result = runner.invoke(cli, [
            "batch", str(d), "-O", str(out),
        ])
        assert result.exit_code == 0
        assert "处理 0 个文件" in result.output
        assert "跳过 2 个" in result.output

    def test_batch_reports_summary(self, runner, batch_dir, out_dir):
        """--reports summary 只生成主报告 CSV + MD。"""
        result = runner.invoke(cli, [
            "batch", str(batch_dir), "-O", str(out_dir), "--reports", "summary",
        ])
        assert result.exit_code == 0
        # 每个文件 2 个报告文件
        report_files = list(out_dir.iterdir())
        assert len(report_files) == 6  # 3 files × 2 reports
        # 应有 analysis 文件，不应有 shadow_detail
        assert (out_dir / "huawei_simple_analysis.csv").exists()
        assert (out_dir / "huawei_simple_analysis.md").exists()
        assert not (out_dir / "huawei_simple_shadow_detail.csv").exists()

    def test_batch_reports_csv_only(self, runner, batch_dir, out_dir):
        """--reports csv 只生成 CSV。"""
        result = runner.invoke(cli, [
            "batch", str(batch_dir), "-O", str(out_dir), "--reports", "csv",
        ])
        assert result.exit_code == 0
        report_files = list(out_dir.iterdir())
        assert len(report_files) == 3  # 3 files × 1 csv
        for f in report_files:
            assert f.name.endswith("_analysis.csv")

    def test_batch_reports_markdown_only(self, runner, batch_dir, out_dir):
        """--reports markdown 只生成 Markdown。"""
        result = runner.invoke(cli, [
            "batch", str(batch_dir), "-O", str(out_dir), "--reports", "markdown",
        ])
        assert result.exit_code == 0
        report_files = list(out_dir.iterdir())
        assert len(report_files) == 3  # 3 files × 1 md
        for f in report_files:
            assert f.name.endswith("_analysis.md")

    def test_batch_reports_shadow_detail(self, runner, batch_dir, out_dir):
        """--reports shadow-detail 只生成影子详细报告。"""
        result = runner.invoke(cli, [
            "batch", str(batch_dir), "-O", str(out_dir), "--reports", "shadow-detail",
        ])
        assert result.exit_code == 0
        report_files = list(out_dir.iterdir())
        assert len(report_files) == 6  # 3 files × 2 shadow reports
        for f in report_files:
            assert "shadow_detail" in f.name

    def test_batch_recursive(self, runner, tmp_path):
        """--recursive 递归扫描子目录。"""
        import shutil
        root = tmp_path / "configs"
        root.mkdir()
        sub = root / "subdir"
        sub.mkdir()
        # 根目录放一个文件
        shutil.copy(FIXTURES_DIR / "huawei_simple.cfg", root / "huawei_simple.cfg")
        # 子目录放一个文件
        shutil.copy(FIXTURES_DIR / "fortinet_simple.cfg", sub / "fortinet_simple.cfg")
        out = tmp_path / "out"
        result = runner.invoke(cli, [
            "batch", str(root), "-O", str(out), "--recursive", "--reports", "csv",
        ])
        assert result.exit_code == 0
        assert "处理 2 个文件" in result.output
        # 两个文件都生成了报告
        report_files = list(out.iterdir())
        assert len(report_files) == 2

    def test_batch_vendor_override(self, runner, tmp_path):
        """--vendor 指定厂商覆盖自动检测。"""
        import shutil
        d = tmp_path / "configs"
        d.mkdir()
        shutil.copy(FIXTURES_DIR / "huawei_simple.cfg", d / "huawei_simple.cfg")
        out = tmp_path / "out"
        result = runner.invoke(cli, [
            "batch", str(d), "-O", str(out),
            "--vendor", "huawei", "--reports", "csv",
        ])
        assert result.exit_code == 0
        assert "处理 1 个文件" in result.output
        assert (out / "huawei_simple_analysis.csv").exists()

    def test_batch_output_dir_created(self, runner, batch_dir, tmp_path):
        """输出目录不存在时自动创建。"""
        out = tmp_path / "nested" / "deep" / "reports"
        assert not out.exists()
        result = runner.invoke(cli, [
            "batch", str(batch_dir), "-O", str(out), "--reports", "csv",
        ])
        assert result.exit_code == 0
        assert out.exists()
        assert len(list(out.iterdir())) == 3

    def test_batch_parse_error_continues(self, runner, tmp_path):
        """某文件解析失败不影响其他文件的处理。"""
        import shutil
        d = tmp_path / "configs"
        d.mkdir()
        # 一个正常文件
        shutil.copy(FIXTURES_DIR / "huawei_simple.cfg", d / "good.cfg")
        # 一个会被识别为某厂商但解析会出问题的文件（强制指定错误厂商）
        # 制造一个看起来像 Cisco ASA 但内容损坏的文件
        bad = d / "bad_cisco.cfg"
        bad.write_text(
            "ASA Version 9.8\n"
            "nameif outside\n"
            "access-list BROKEN extended permit\n",  # incomplete ACL
            encoding="utf-8",
        )
        out = tmp_path / "out"
        result = runner.invoke(cli, [
            "batch", str(d), "-O", str(out), "--reports", "csv",
        ])
        assert result.exit_code == 0
        # good.cfg 应该正常处理
        assert "处理" in result.output
        # 报告目录应有至少一个文件
        assert len(list(out.iterdir())) >= 1
