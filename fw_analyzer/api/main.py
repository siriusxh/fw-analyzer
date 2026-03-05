"""
fw_analyzer/api/main.py

FastAPI 应用入口。

启动方式：
  uvicorn fw_analyzer.api.main:app --reload

或通过 CLI：
  fw-analyzer serve [--host 0.0.0.0] [--port 8000]

API 文档（启动后访问）：
  http://localhost:8000/docs   (Swagger UI)
  http://localhost:8000/redoc  (ReDoc)
"""
from __future__ import annotations

try:
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
except ImportError:
    raise ImportError(
        "FastAPI 未安装。请运行: pip install 'fw-analyzer[api]'"
    )

from .routers import parse, analyze, trace, sessions

# ------------------------------------------------------------------
# 应用实例
# ------------------------------------------------------------------

app = FastAPI(
    title="fw-analyzer API",
    description=(
        "多厂商防火墙配置分析工具 REST API。\n\n"
        "支持华为 USG、Cisco ASA、Palo Alto PAN-OS、Fortinet FortiGate。\n\n"
        "**两种使用模式**：\n"
        "- **无状态**：`POST /parse` / `POST /analyze` / `POST /trace` — 上传即分析，不保留历史。\n"
        "- **有状态**：`POST /sessions` 创建会话后，对会话 ID 执行分析/Trace，支持多次查询同一份配置。"
    ),
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# ------------------------------------------------------------------
# CORS（开发环境宽松，生产部署时应收窄 allow_origins）
# ------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------------------------------
# 路由注册
# ------------------------------------------------------------------

app.include_router(parse.router)
app.include_router(analyze.router)
app.include_router(trace.router)
app.include_router(sessions.router)


# ------------------------------------------------------------------
# 健康检查
# ------------------------------------------------------------------

@app.get("/health", tags=["system"], summary="健康检查")
def health() -> dict:
    """返回服务运行状态。"""
    return {"status": "ok", "version": app.version}
