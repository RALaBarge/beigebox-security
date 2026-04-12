"""
BeigeBox Security — Unified security orchestration for LLM/RAG stacks.

Provides 4 core security tools:
- RAG Poisoning Detection: Embedding anomaly detection
- MCP Parameter Validation: Tool injection prevention
- API Anomaly Detection: Token extraction detection
- Memory Integrity Validation: Conversation tampering detection
"""

__version__ = "0.1.0"
__author__ = "Jinx"

from beigebox_security.api import create_app

__all__ = ["create_app"]
