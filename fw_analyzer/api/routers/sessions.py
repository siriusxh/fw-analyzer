"""
fw_analyzer/api/routers/sessions.py

会话路由（有状态模式）。

POST   /sessions          - 创建会话（上传配置，解析后存储）
GET    /sessions          - 列出所有会话
GET    /sessions/{id}     - 获取会话信息
DELETE /sessions/{id}     - 删除会话
POST   /sessions/{id}/analyze  - 对会话中的配置执行分析
POST   /sessions/{id}/trace    - 对会话中的配置执行 Trace
"""
from __future__ import annotations

import uuid
from datetime import datetime

try:
    from fastapi import APIRouter, HTTPException, Depends
except ImportError:
    raise ImportError("请运行: pip install 'fw-analyzer[api]'")

from ...parsers import get_parser, detect_vendor
from ...config import AnalyzerConfig
from ...analyzers.engine import AnalysisEngine
from ...trace import TraceEngine, TraceQuery
from ..dependencies import get_session_store, get_config, InMemorySessionStore
from ..schemas import (
    SessionCreateRequest, SessionResponse, SessionListResponse,
    AnalyzeResponse, AnalyzeRequest,
    TraceRequest, TraceResultSchema,
    RuleSchema, WarningSchema,
)

router = APIRouter(prefix="/sessions", tags=["sessions"])


# ------------------------------------------------------------------
# 会话管理
# ------------------------------------------------------------------

@router.post("", response_model=SessionResponse, summary="创建会话")
def create_session(
    request: SessionCreateRequest,
    store: InMemorySessionStore = Depends(get_session_store),
) -> SessionResponse:
    """上传配置文本，解析后存入会话存储。返回会话 ID。"""
    vendor = request.vendor
    if vendor == "auto":
        vendor = detect_vendor(request.content) or "unknown"

    try:
        parser = get_parser(vendor)
        parse_result = parser.parse(request.content, source_file=request.source_file)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"解析失败: {e}")

    session_id = str(uuid.uuid4())
    store.put(session_id, parse_result)

    return SessionResponse(
        session_id=session_id,
        vendor=parse_result.vendor,
        source_file=parse_result.source_file,
        rule_count=parse_result.rule_count,
        created_at=datetime.now().isoformat(),
    )


@router.get("", response_model=SessionListResponse, summary="列出所有会话")
def list_sessions(
    store: InMemorySessionStore = Depends(get_session_store),
) -> SessionListResponse:
    """列出所有活跃会话 ID。"""
    sessions = []
    for sid in store.list_sessions():
        result = store.get(sid)
        if result:
            sessions.append(SessionResponse(
                session_id=sid,
                vendor=result.vendor,
                source_file=result.source_file,
                rule_count=result.rule_count,
                created_at="",
            ))
    return SessionListResponse(sessions=sessions)


@router.delete("/{session_id}", summary="删除会话")
def delete_session(
    session_id: str,
    store: InMemorySessionStore = Depends(get_session_store),
) -> dict:
    """删除指定会话。"""
    if not store.delete(session_id):
        raise HTTPException(status_code=404, detail=f"会话 {session_id!r} 不存在。")
    return {"deleted": session_id}


# ------------------------------------------------------------------
# 会话操作
# ------------------------------------------------------------------

@router.post("/{session_id}/analyze", response_model=AnalyzeResponse, summary="分析会话规则")
def analyze_session(
    session_id: str,
    request: AnalyzeRequest,
    store: InMemorySessionStore = Depends(get_session_store),
    config: AnalyzerConfig = Depends(get_config),
) -> AnalyzeResponse:
    """对已存储的会话执行规则质量分析。"""
    parse_result = store.get(session_id)
    if not parse_result:
        raise HTTPException(status_code=404, detail=f"会话 {session_id!r} 不存在。")

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
        parse_warnings=[
            WarningSchema(code=w.code, message=w.message, severity=w.severity.value)
            for w in result.parse_warnings
        ],
        analysis_warnings=[
            WarningSchema(code=w.code, message=w.message, severity=w.severity.value)
            for w in result.analysis_warnings
        ],
        rules=[
            RuleSchema(
                seq=r.seq,
                rule_id=r.raw_rule_id,
                rule_name=r.rule_name,
                vendor=r.vendor,
                action=r.action,
                src_ip=r.src_ip_str(),
                dst_ip=r.dst_ip_str(),
                services=r.service_str(),
                src_zone=r.src_zone,
                dst_zone=r.dst_zone,
                enabled=r.enabled,
                comment=r.comment,
                analysis_tags=r.analysis_tags,
                warnings=[
                    WarningSchema(code=w.code, message=w.message, severity=w.severity.value)
                    for w in r.warnings
                ],
            )
            for r in result.rules
        ],
    )


@router.post("/{session_id}/trace", response_model=TraceResultSchema, summary="Trace 访问需求")
def trace_session(
    session_id: str,
    request: TraceRequest,
    store: InMemorySessionStore = Depends(get_session_store),
) -> TraceResultSchema:
    """对已存储的会话执行 Trace。"""
    parse_result = store.get(session_id)
    if not parse_result:
        raise HTTPException(status_code=404, detail=f"会话 {session_id!r} 不存在。")

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
