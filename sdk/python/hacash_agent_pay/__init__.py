"""Hacash Agent Pay — Python SDK for AI agents."""

from .client import AgentPayClient, AgentPayError
from .close import (
    CLOSE_INTENT_SCHEMA,
    assert_ready_for_close,
    build_close_intent,
    close_checklist,
)
from .crypto import HacashKey, build_agent_intent_message, sign_agent_intent

__all__ = [
    "AgentPayClient",
    "AgentPayError",
    "HacashKey",
    "build_agent_intent_message",
    "sign_agent_intent",
    "CLOSE_INTENT_SCHEMA",
    "build_close_intent",
    "assert_ready_for_close",
    "close_checklist",
]
__version__ = "0.2.0"
