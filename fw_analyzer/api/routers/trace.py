"""
fw_analyzer/api/routers/trace.py

Trace 路由（无状态）。

POST /trace
  - 上传配置文本 + 查询条件
  - 返回命中规则
"""
from __future__ import annotations

try:
    from fastapi import APIRouter, HTTPException
except ImportError:
    raise ImportError("请运行: pip install 'fw-analyzer[api]'")

from ...parsers import get_parser, detect_vendor
from ...trace import TraceEngine, TraceQuery
from ..schemas import TraceRequest, TraceResultSchema

router = APIRouter(prefix="/trace", tags=["trace"])


@router.post("", response_model=TraceResultSchema, summary="Trace 访问需求")
def trace(request: TraceRequest) -> TraceResultSchema:
    """
    在配置文本中 Trace 单条访问需求，返回第一条命中规则。

    - **src_ip**: 源 IP（CIDR，如 10.0.0.1 或 10.0.0.1/32）
    - **dst_ip**: 目的 IP（CIDR）
    - **protocol**: tcp / udp / icmp / any
    - **dst_port**: 目的端口（0 表示 any）
    - **first_match_only**: true 返回第一条命中；false 返回全部（仅返回第一条在此响应中）
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
        parse_result = parser.parse(request.content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"解析失败: {e}")

    query = TraceQuery(
        src_ip=request.src_ip,
        dst_ip=request.dst_ip,
        protocol=request.protocol,
        dst_port=request.dst_port,
        src_port=request.src_port,
    )

    engine = TraceEngine(parse_result.rules)
    result = engine.trace(query, first_match_only=request.first_match_only)

    return TraceResultSchema(
        src_ip=query.src_ip,
        dst_ip=query.dst_ip,
        protocol=query.protocol,
        dst_port=query.dst_port,
        src_port=query.src_port,
        matched=result.matched,
        matched_rule_id=result.matched_rule.raw_rule_id if result.matched_rule else "",
        matched_rule_name=result.matched_rule.rule_name if result.matched_rule else "",
        matched_seq=result.matched_rule.seq if result.matched_rule else -1,
        action=result.action,
        match_note=result.match_note,
    )
