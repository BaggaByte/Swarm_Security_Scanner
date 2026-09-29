"""Redact likely credentials before repository content reaches an LLM or UI."""

from __future__ import annotations

import re


_ASSIGNMENT_SECRET = re.compile(
    r"(?im)(?P<prefix>(?P<keyquote>['\"]?)\b(?:[A-Z0-9_.-]*(?:API[_-]?KEY|ACCESS[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|PRIVATE[_-]?KEY|AUTH)[A-Z0-9_.-]*)\b(?P=keyquote)\s*[:=]\s*)"
    r"(?:(?P<quote>['\"])[^'\"\r\n]*?(?P=quote)|(?=[A-Za-z0-9./+=-]{20,160}(?:\s*(?:#.*)?$))(?=[A-Za-z0-9./+=-]*\d)[A-Za-z0-9./+=-]{20,160})(?=\s*(?:#.*)?$)"
)
_BEARER_SECRET = re.compile(r"(?i)(\bBearer\s+)[A-Za-z0-9._~+/=-]{12,}")
_PEM_BLOCK = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)


def redact_sensitive_content(content: str) -> str:
    """Keep key names and structure while masking likely secret values."""
    content = _PEM_BLOCK.sub("[REDACTED PRIVATE KEY]", content)
    content = _ASSIGNMENT_SECRET.sub(lambda match: f"{match.group('prefix')}[REDACTED]", content)
    return _BEARER_SECRET.sub(r"\1[REDACTED]", content)
