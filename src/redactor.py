"""Data masking / redaction of detected findings inside the source text."""

from __future__ import annotations

from .detector import Finding


def redact_text(text: str, findings: list[Finding], mode: str = "mask") -> str:
    """
    Produce a sanitized copy of the document.

    mode="mask"   -> partial masking (keeps last digits etc.), preserves layout
    mode="redact" -> replace every finding with [ENTITY_TYPE]
    """
    # Replace from the end so earlier offsets stay valid.
    out = text
    for f in sorted(findings, key=lambda f: f.start, reverse=True):
        replacement = f.masked if mode == "mask" else f"[{f.entity_type}]"
        out = out[:f.start] + replacement + out[f.end:]
    return out
