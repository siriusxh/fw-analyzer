"""
fw_analyzer/api/routers/parse.py

解析路由（无状态）。

POST /parse
  - 上传配置文本
  - 返回解析结果（规则列表 + 警告）
"""
from __future__ import annotations

try:
    from fastapi import APIRouter, HTTPException
except ImportError:
    raise ImportError("请运行: pip install 'fw-analyzer[api]'")

from ...parsers import get_parser, detect_vendor
from ...parsers.base import ParseError
from ..schemas import ParseRequest, ParseResponse, RuleSchema, WarningSchema

router = APIRouter(prefix="/parse", tags=["parse"])


@router.post("", response_model=ParseResponse, summary="解析防火墙配置")
def parse_config(request: ParseRequest) -> ParseResponse:
    """
    解析防火墙配置文本，返回规则列表。

    - **content**: 配置文本内容
    - **vendor**: 厂商标识（auto 表示自动识别）
    - **source_file**: 原始文件名（仅用于报告）
    """
    vendor = request.vendor
    if vendor == "auto":
        vendor = detect_vendor(request.content)
        if not vendor:
            raise HTTPException(
                status_code=422,
                detail="无法自动识别厂商，请在 vendor 字段明确指定。",
            )

    try:
        parser = get_parser(vendor)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    try:
        result = parser.parse(request.content, source_file=request.source_file)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"解析失败: {e}")

    return ParseResponse(
        vendor=result.vendor,
        source_file=result.source_file,
        rule_count=result.rule_count,
        enabled_rule_count=result.enabled_rule_count,
        warnings=[WarningSchema(code=w.code, message=w.message, severity=w.severity.value)
                  for w in result.warnings],
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
        warnings=[WarningSchema(code=w.code, message=w.message, severity=w.severity.value)
                  for w in rule.warnings],
    )
