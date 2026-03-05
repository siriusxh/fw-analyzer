"""
fw_analyzer/api/dependencies.py

FastAPI 依赖注入：配置加载、SessionStore。
"""
from __future__ import annotations

from typing import Optional, Protocol, runtime_checkable

try:
    from fastapi import Depends, HTTPException
except ImportError:
    raise ImportError("请运行: pip install 'fw-analyzer[api]'")

from ..config import AnalyzerConfig, load_config
from ..models.rule import ParseResult


# ------------------------------------------------------------------
# SessionStore Protocol（抽象存储，支持替换为 Redis/DB）
# ------------------------------------------------------------------

@runtime_checkable
class SessionStore(Protocol):
    """
    会话存储 Protocol。

    实现者需提供以下方法：
      get(session_id) → ParseResult | None
      put(session_id, result) → None
      delete(session_id) → bool
      list_sessions() → list[str]
    """

    def get(self, session_id: str) -> Optional[ParseResult]:
        ...

    def put(self, session_id: str, result: ParseResult) -> None:
        ...

    def delete(self, session_id: str) -> bool:
        ...

    def list_sessions(self) -> list[str]:
        ...


# ------------------------------------------------------------------
# 内存 SessionStore 实现（默认）
# ------------------------------------------------------------------

class InMemorySessionStore:
    """基于内存的简单会话存储（进程重启后丢失）。"""

    def __init__(self) -> None:
        self._store: dict[str, ParseResult] = {}

    def get(self, session_id: str) -> Optional[ParseResult]:
        return self._store.get(session_id)

    def put(self, session_id: str, result: ParseResult) -> None:
        self._store[session_id] = result

    def delete(self, session_id: str) -> bool:
        if session_id in self._store:
            del self._store[session_id]
            return True
        return False

    def list_sessions(self) -> list[str]:
        return list(self._store.keys())


# 全局默认 session store（应用启动时可替换）
_default_store = InMemorySessionStore()


def get_session_store() -> InMemorySessionStore:
    """FastAPI 依赖：获取 SessionStore 实例。"""
    return _default_store


def get_config() -> AnalyzerConfig:
    """FastAPI 依赖：获取全局 AnalyzerConfig。"""
    return load_config()
