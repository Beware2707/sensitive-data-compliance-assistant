"""
Sensitive data detection engine.

Layered approach:
  1. Regex candidate matching (high recall)
  2. Algorithmic validation (Verhoeff for Aadhaar, Luhn for cards,
     structural rules for PAN/IFSC) to cut false positives
  3. Context-window keyword scoring for ambiguous entities
     (bank accounts, employee IDs, passwords)

Every finding carries its position, the matched value, a masked
rendering, a severity weight and a confidence score.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict


# --------------------------------------------------------------------------
# Finding model
# --------------------------------------------------------------------------

@dataclass
class Finding:
    entity_type: str          # machine name, e.g. "AADHAAR"
    label: str                # human name, e.g. "Aadhaar Number"
    value: str                # raw matched text
    masked: str               # safe-to-display rendering
    start: int                # char offset in source text
    end: int
    severity: str             # HIGH | MEDIUM | LOW
    weight: int               # contribution to the document risk score
    confidence: float         # 0.0 - 1.0
    context: str = field(default="", repr=False)  # surrounding snippet

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------
# Validation algorithms
# --------------------------------------------------------------------------

_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def verhoeff_valid(number: str) -> bool:
    """Aadhaar numbers embed a Verhoeff checksum in the last digit."""
    c = 0
    for i, digit in enumerate(reversed(number)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(digit)]]
    return c == 0


def luhn_valid(number: str) -> bool:
    """Credit/debit card numbers use the Luhn (mod-10) checksum."""
    digits = [int(d) for d in number]
    odd = digits[-1::-2]
    even = [sum(divmod(d * 2, 10)) for d in digits[-2::-2]]
    return (sum(odd) + sum(even)) % 10 == 0


def pan_valid(pan: str) -> bool:
    """4th character of a PAN encodes the holder type (P=person, C=company...)."""
    return pan[3] in "PCHABGJLFT"


# --------------------------------------------------------------------------
# Masking helpers
# --------------------------------------------------------------------------

def _mask_keep_last(value: str, keep: int = 4, char: str = "X") -> str:
    digits_seen = 0
    total_digits = sum(ch.isdigit() for ch in value)
    out = []
    for ch in value:
        if ch.isdigit():
            digits_seen += 1
            out.append(ch if digits_seen > total_digits - keep else char)
        else:
            out.append(ch)
    return "".join(out)


def _mask_email(value: str) -> str:
    local, _, domain = value.partition("@")
    if len(local) <= 2:
        return "*" * len(local) + "@" + domain
    return local[0] + "*" * (len(local) - 2) + local[-1] + "@" + domain


def _mask_full(value: str) -> str:
    return "[REDACTED]"


def _mask_pan(value: str) -> str:
    return value[:2] + "XXX" + "XXXX" + value[-1]


# --------------------------------------------------------------------------
# Context scoring
# --------------------------------------------------------------------------

def _context_score(text: str, start: int, end: int, keywords: list[str],
                   window: int = 60) -> float:
    """Fraction boost when entity-related keywords appear near the match."""
    lo = max(0, start - window)
    hi = min(len(text), end + window)
    ctx = text[lo:hi].lower()
    return 1.0 if any(k in ctx for k in keywords) else 0.0


def _snippet(text: str, start: int, end: int, window: int = 45) -> str:
    lo = max(0, start - window)
    hi = min(len(text), end + window)
    return ("…" if lo > 0 else "") + text[lo:hi].replace("\n", " ") + ("…" if hi < len(text) else "")


# --------------------------------------------------------------------------
# Detector definitions
# --------------------------------------------------------------------------

# Each entry: label, regex, severity, weight, validator, masker, context keywords
_AADHAAR_RE = re.compile(r"\b([2-9]\d{3})[\s-]?(\d{4})[\s-]?(\d{4})\b")
_PAN_RE = re.compile(r"\b([A-Z]{5}\d{4}[A-Z])\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE_RE = re.compile(r"(?<!\d)(?:\+91[\s-]?|0)?([6-9]\d{4})[\s-]?(\d{5})(?!\d)")
_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_IFSC_RE = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")
_ACCOUNT_RE = re.compile(r"\b\d{9,18}\b")
_EMP_ID_RE = re.compile(r"\b(?:EMP|EMPL|E)[-/]?\d{3,8}\b", re.IGNORECASE)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b")
# No leading \b: must also match prefixed identifiers like db_password / prod-secret.
_GENERIC_SECRET_RE = re.compile(
    r"(?i)(password|passwd|pwd|secret|api[_ -]?key|apikey|access[_ -]?token|"
    r"auth[_ -]?token|private[_ -]?key|client[_ -]?secret)\b\s*[:=]\s*[\"']?"
    r"([^\s\"',;]{6,})"
)
_KNOWN_KEY_RES = [
    ("AWS Access Key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("OpenAI/Generic sk- Key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Anthropic API Key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
]

_CONFIDENTIAL_TERMS = [
    "confidential", "strictly private", "internal use only", "internal only",
    "do not distribute", "do not share", "trade secret", "proprietary",
    "nda", "non-disclosure", "classified", "restricted circulation",
    "salary", "compensation", "ctc", "offer letter", "acquisition",
    "merger", "unreleased", "pre-release", "embargo",
]
_CONFIDENTIAL_RE = re.compile(
    r"(?i)\b(" + "|".join(re.escape(t) for t in _CONFIDENTIAL_TERMS) + r")\b"
)

_BANK_KEYWORDS = ["account", "a/c", "acct", "bank", "ifsc", "branch", "neft", "rtgs", "upi"]
_EMP_KEYWORDS = ["employee", "emp id", "staff", "personnel", "hr", "payroll"]


# --------------------------------------------------------------------------
# Main entry point
# --------------------------------------------------------------------------

def detect(text: str) -> list[Finding]:
    findings: list[Finding] = []
    claimed: set[tuple[int, int]] = set()   # spans already attributed

    def overlaps(start: int, end: int) -> bool:
        return any(s < end and start < e for s, e in claimed)

    def add(finding: Finding) -> None:
        claimed.add((finding.start, finding.end))
        finding.context = _snippet(text, finding.start, finding.end)
        findings.append(finding)

    # --- Known API key formats (checked first: very distinctive) -----------
    for label, pattern in _KNOWN_KEY_RES:
        for m in pattern.finditer(text):
            add(Finding("API_KEY", f"API Key ({label})", m.group(), _mask_full(m.group()),
                        m.start(), m.end(), "HIGH", 10, 0.98))

    for m in _JWT_RE.finditer(text):
        if not overlaps(m.start(), m.end()):
            add(Finding("API_KEY", "JWT Token", m.group(), _mask_full(m.group()),
                        m.start(), m.end(), "HIGH", 10, 0.95))

    # --- Passwords / generic secrets ---------------------------------------
    for m in _GENERIC_SECRET_RE.finditer(text):
        s, e = m.start(2), m.end(2)
        if overlaps(s, e):
            continue
        kind = m.group(1).lower()
        label = "Password" if "pass" in kind or "pwd" in kind else "Secret / API Key"
        add(Finding("PASSWORD" if label == "Password" else "API_KEY",
                    label, m.group(2), _mask_full(m.group(2)),
                    s, e, "HIGH", 10, 0.9))

    # --- Credit / debit cards (Luhn-validated) ------------------------------
    for m in _CARD_RE.finditer(text):
        digits = re.sub(r"[ -]", "", m.group())
        if not (13 <= len(digits) <= 19) or overlaps(m.start(), m.end()):
            continue
        if luhn_valid(digits) and digits[0] in "23456":
            add(Finding("CREDIT_CARD", "Credit/Debit Card Number", m.group().strip(),
                        _mask_keep_last(m.group().strip()), m.start(), m.end(),
                        "HIGH", 10, 0.95))

    # --- Aadhaar (Verhoeff-validated) ---------------------------------------
    for m in _AADHAAR_RE.finditer(text):
        digits = "".join(m.groups())
        if overlaps(m.start(), m.end()):
            continue
        valid = verhoeff_valid(digits)
        ctx = _context_score(text, m.start(), m.end(), ["aadhaar", "aadhar", "uid", "uidai"])
        if valid or ctx:
            add(Finding("AADHAAR", "Aadhaar Number", m.group(),
                        _mask_keep_last(m.group()), m.start(), m.end(),
                        "HIGH", 10, 0.97 if valid else 0.7))

    # --- PAN -----------------------------------------------------------------
    for m in _PAN_RE.finditer(text):
        if overlaps(m.start(), m.end()) or not pan_valid(m.group()):
            continue
        add(Finding("PAN", "PAN Number", m.group(), _mask_pan(m.group()),
                    m.start(), m.end(), "HIGH", 8, 0.95))

    # --- IFSC (bank routing) --------------------------------------------------
    for m in _IFSC_RE.finditer(text):
        if not overlaps(m.start(), m.end()):
            add(Finding("BANK_DETAILS", "IFSC Code", m.group(), m.group()[:4] + "0XXXXXX",
                        m.start(), m.end(), "MEDIUM", 5, 0.95))

    # --- Emails ----------------------------------------------------------------
    for m in _EMAIL_RE.finditer(text):
        if not overlaps(m.start(), m.end()):
            add(Finding("EMAIL", "Email Address", m.group(), _mask_email(m.group()),
                        m.start(), m.end(), "MEDIUM", 3, 0.98))

    # --- Phone numbers -----------------------------------------------------------
    for m in _PHONE_RE.finditer(text):
        if overlaps(m.start(), m.end()):
            continue
        digits = m.group(1) + m.group(2)
        ctx = _context_score(text, m.start(), m.end(),
                             ["phone", "mobile", "contact", "call", "whatsapp", "tel"])
        has_prefix = m.group().strip().startswith(("+", "0"))
        formatted = "-" in m.group() or " " in m.group().strip()
        if ctx or has_prefix or formatted:
            add(Finding("PHONE", "Phone Number", m.group().strip(),
                        _mask_keep_last(m.group().strip()), m.start(), m.end(),
                        "MEDIUM", 3, 0.9 if ctx else 0.75))

    # --- Bank account numbers (context-gated: bare digit runs are ambiguous) ------
    for m in _ACCOUNT_RE.finditer(text):
        if overlaps(m.start(), m.end()):
            continue
        if _context_score(text, m.start(), m.end(), _BANK_KEYWORDS):
            add(Finding("BANK_DETAILS", "Bank Account Number", m.group(),
                        _mask_keep_last(m.group()), m.start(), m.end(),
                        "HIGH", 8, 0.85))

    # --- Employee IDs ---------------------------------------------------------------
    for m in _EMP_ID_RE.finditer(text):
        if overlaps(m.start(), m.end()):
            continue
        ctx = _context_score(text, m.start(), m.end(), _EMP_KEYWORDS, window=120)
        starts_emp = m.group().upper().startswith("EMP")
        if starts_emp or ctx:
            add(Finding("EMPLOYEE_ID", "Employee ID", m.group(),
                        m.group()[:3] + "XXXX", m.start(), m.end(),
                        "LOW", 2, 0.9 if starts_emp else 0.7))

    # --- Confidential business language ----------------------------------------------
    for m in _CONFIDENTIAL_RE.finditer(text):
        if not overlaps(m.start(), m.end()):
            add(Finding("CONFIDENTIAL", "Confidential Business Term", m.group(),
                        m.group(), m.start(), m.end(), "MEDIUM", 2, 0.8))

    findings.sort(key=lambda f: f.start)
    return findings


def summarize_findings(findings: list[Finding]) -> dict[str, dict]:
    """Aggregate counts per entity label, keeping the max severity/weight."""
    agg: dict[str, dict] = {}
    for f in findings:
        entry = agg.setdefault(f.label, {
            "entity_type": f.entity_type, "count": 0,
            "severity": f.severity, "examples": [],
        })
        entry["count"] += 1
        if len(entry["examples"]) < 3:
            entry["examples"].append(f.masked)
    return agg
