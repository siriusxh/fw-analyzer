"""
fw_analyzer/api/routers/analyze.py

分析路由（无状态）。

POST /analyze
  - 上传配置文本
  - 执行全量分析（影子/冗余/过宽/合规）
  - 返回分析结果
"""
from __future__ import annotations

try:
    from fastapi import APIRouter, HTTPException
except ImportError:
    raise ImportError("请运行: pip install 'fw-analyzer[api]'")

from ...parsers import get_parser, detect_vendor
from ...config import AnalyzerConfig
from ...analyzers.engine import AnalysisEngine
from ..schemas import AnalyzeRequest, AnalyzeResponse, RuleSchema, WarningSchema

router = APIRouter(prefix="/analyze", tags=["analyze"])


@router.post("", response_model=AnalyzeResponse, summary="分析防火墙规则质量")
def analyze_config(request: AnalyzeRequest) -> AnalyzeResponse:
    """
    解析并分析防火墙配置，返回带质量标签的规则列表。

    分析包含：影子规则、冗余规则、过宽规则、合规检查。
    """
    vendor = request.vendor
    if vendor == "auto":
        vendor = detect_vendor(request.content)
        if not vendor:
            raise HTTPException(status_code=422, detail="无法自动识别厂商。")

    try:
        parser = get_parser(vendor)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    try:
        parse_result = parser.parse(request.content, source_file=request.source_file)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"解析失败: {e}")

    # 构建配置（支持请求中自定义端口）
    config = AnalyzerConfig()
    if request.high_risk_tcp_ports is not None:
        config.high_risk_tcp_ports = request.high_risk_tcp_ports
    if request.high_risk_udp_ports is not None:
        config.high_risk_udp_ports = request.high_risk_udp_ports

    engine = AnalysisEngine(config)
    result = engine.analyze(parse_result)

    return AnalyzeResponse(
        vendor=result.vendor,
        source_file=result.source_file,
        rule_count=result.rule_count,
        tagged_rule_count=result.tagged_rule_count,
        issue_rule_count=result.issue_rule_count,
        info_rule_count=result.info_rule_count,
        parse_warnings=[
            WarningSchema(code=w.code, message=w.message, severity=w.severity.value)
            for w in result.parse_warnings
        ],
        analysis_warnings=[
            WarningSchema(code=w.code, message=w.message, severity=w.severity.value)
            for w in result.analysis_warnings
        ],
        rules=[_rule_to_schema(r) for r in result.rules],
    )


def _rule_to_schema(rule) -> RuleSchema:
    return RuleSchema(
        seq=rule.seq,
        rule_id=rule.raw_rule_id,
        rule_name=rule.rule_name,
        vendor=rule.vendor,
        action=rule.action,
        src_ip=rule.src_ip_str(),
        dst_ip=rule.dst_ip_str(),
        services=rule.service_str(),
        src_zone=rule.src_zone,
        dst_zone=rule.dst_zone,
        enabled=rule.enabled,
        comment=rule.comment,
        analysis_tags=rule.analysis_tags,
        warnings=[
            WarningSchema(code=w.code, message=w.message, severity=w.severity.value)
            for w in rule.warnings
        ],
    )
