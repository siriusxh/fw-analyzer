"""
fw_analyzer/api/schemas.py

API 请求/响应数据模型（Pydantic）。

仅在安装 fw-analyzer[api] 时可用（fastapi + pydantic 可选依赖）。
"""
from __future__ import annotations

from typing import Optional, List

try:
    from pydantic import BaseModel, Field
except ImportError:
    raise ImportError(
        "FastAPI/Pydantic 未安装。请运行: pip install 'fw-analyzer[api]'"
    )


# ------------------------------------------------------------------
# 通用
# ------------------------------------------------------------------

class WarningSchema(BaseModel):
    code: str
    message: str
    severity: str


# ------------------------------------------------------------------
# 解析
# ------------------------------------------------------------------

class ParseRequest(BaseModel):
    """上传配置文本请求。"""
    content: str = Field(..., description="防火墙配置文本内容")
    vendor: str = Field("auto", description="厂商: huawei/cisco-asa/paloalto/fortinet/auto")
    source_file: str = Field("", description="原始文件名（仅用于报告显示）")


class RuleSchema(BaseModel):
    """规则摘要（API 响应）。"""
    seq: int
    rule_id: str
    rule_name: str
    vendor: str
    action: str
    src_ip: str
    dst_ip: str
    services: str
    src_zone: str
    dst_zone: str
    enabled: bool
    log_enabled: bool
    comment: str
    ticket: str
    analysis_tags: List[str]
    warnings: List[WarningSchema]


class ParseResponse(BaseModel):
    """解析结果响应。"""
    vendor: str
    source_file: str
    rule_count: int
    enabled_rule_count: int
    warnings: List[WarningSchema]
    rules: List[RuleSchema]


# ------------------------------------------------------------------
# 分析
# ------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    """分析请求（在 ParseRequest 基础上增加配置项）。"""
    content: str = Field(..., description="防火墙配置文本内容")
    vendor: str = Field("auto", description="厂商标识")
    source_file: str = Field("")
    # 可选：自定义高危端口覆盖
    high_risk_tcp_ports: Optional[List[int]] = Field(None, description="自定义 TCP 高危端口列表")
    high_risk_udp_ports: Optional[List[int]] = Field(None, description="自定义 UDP 高危端口列表")


class AnalyzeResponse(BaseModel):
    """分析结果响应。"""
    vendor: str
    source_file: str
    rule_count: int
    tagged_rule_count: int
    issue_rule_count: int
    info_rule_count: int
    parse_warnings: List[WarningSchema]
    analysis_warnings: List[WarningSchema]
    rules: List[RuleSchema]


# ------------------------------------------------------------------
# Trace
# ------------------------------------------------------------------

class TraceRequest(BaseModel):
    """单条 Trace 查询请求。"""
    content: str = Field(..., description="防火墙配置文本内容")
    vendor: str = Field("auto")
    src_ip: str = Field(..., description="源 IP（CIDR）")
    dst_ip: str = Field(..., description="目的 IP（CIDR）")
    protocol: str = Field("any", description="协议")
    dst_port: int = Field(0, description="目的端口（0 表示 any）")
    src_port: int = Field(0, description="源端口（0 表示 any）")
    first_match_only: bool = Field(True)


class TraceResultSchema(BaseModel):
    """Trace 结果。"""
    src_ip: str
    dst_ip: str
    protocol: str
    dst_port: int
    src_port: int
    matched: bool
    matched_rule_id: str
    matched_rule_name: str
    matched_seq: int
    action: str
    match_note: str


# ------------------------------------------------------------------
# 会话（有状态模式）
# ------------------------------------------------------------------

class SessionCreateRequest(BaseModel):
    """创建会话请求。"""
    content: str
    vendor: str = "auto"
    source_file: str = ""


class SessionResponse(BaseModel):
    """会话信息响应。"""
    session_id: str
    vendor: str
    source_file: str
    rule_count: int
    created_at: str


class SessionListResponse(BaseModel):
    sessions: List[SessionResponse]
