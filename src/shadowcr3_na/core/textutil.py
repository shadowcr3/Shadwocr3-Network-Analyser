from __future__ import annotations

import re


def clean_text(text: str, limit: int = 500) -> str:
    """Tool and file content is untrusted: drop control/non-ASCII characters and truncate."""
    return re.sub(r"[^\x20-\x7e\n]", "?", text)[:limit]
