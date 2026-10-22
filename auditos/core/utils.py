"""
Pure utility functions for identifiers, timestamps, hashing, and validation in AuditOS.
"""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from auditos.core.config import VALID_ID_RE


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format with millisecond precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def future_utc_iso(minutes: int = 30) -> str:
    """Return a future UTC timestamp in ISO-8601 format for task/system leases."""
    dt = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def validate_identifier(value: Optional[str], field_name: str = "id") -> Optional[str]:
    """Validate that an identifier or slug contains only safe alphanumeric, underscore, or hyphen characters (RF-03)."""
    if value is None or value == "":
        return None
    val = str(value).strip()
    if not VALID_ID_RE.match(val):
        raise ValueError(
            f"Invalid {field_name} '{val}': must be 1-64 characters matching [a-zA-Z0-9_-]."
        )
    return val


def slugify(value: str) -> str:
    """Create a URL/CLI-friendly slug from a name."""
    s = re.sub(r"[^a-zA-Z0-9\s_-]", "", value.strip().lower())
    s = re.sub(r"[\s_]+", "-", s)
    cleaned = s.strip("-")[:64].strip("-")
    return cleaned or f"item-{uuid.uuid4().hex[:8]}"


def short_id(prefix: str) -> str:
    """Generate a readable unique identifier with 48 bits (12 hex chars) of entropy (F-27)."""
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def validate_health_score(score: Optional[int]) -> Optional[int]:
    """Validate that health_score is None or an integer between 0 and 100 inclusive (F-25)."""
    if score is None or score == "":
        return None
    val = int(score)
    if val < 0 or val > 100:
        raise ValueError(f"health_score must be between 0 and 100 (got {val}).")
    return val


def get_git_commit_sha(repo_path: Optional[str] = None) -> str:
    """Attempt to detect the current HEAD git commit SHA for evidence provenance."""
    try:
        cmd = ["git", "rev-parse", "HEAD"]
        cwd = repo_path if repo_path and os.path.isdir(repo_path) else None
        res = subprocess.run(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=1.5,
        )
        if res.returncode == 0:
            return res.stdout.strip()
    except Exception:
        pass
    return ""


def compute_span_hash(code_snippet: Optional[str]) -> str:
    """Compute a deterministic 16-character SHA-256 fingerprint of a code snippet or span."""
    if not code_snippet or not str(code_snippet).strip():
        return ""
    return hashlib.sha256(str(code_snippet).strip().encode("utf-8")).hexdigest()[:16]
