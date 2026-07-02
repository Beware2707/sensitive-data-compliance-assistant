"""Append-only JSONL audit log of scan and query events.

Only metadata is logged — never raw sensitive values. File hashes let an
auditor prove which document was scanned without retaining its contents.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone

AUDIT_LOG_PATH = os.environ.get("AUDIT_LOG_PATH", "audit_log.jsonl")


def file_sha256(file_bytes: bytes) -> str:
    return hashlib.sha256(file_bytes).hexdigest()


def log_event(event_type: str, **details) -> dict:
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event_type,
        **details,
    }
    try:
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass  # read-only deployment filesystems: keep the app functional
    return record


def read_log(limit: int = 200) -> list[dict]:
    if not os.path.exists(AUDIT_LOG_PATH):
        return []
    records = []
    with open(AUDIT_LOG_PATH, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return records[-limit:]
