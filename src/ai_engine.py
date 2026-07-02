"""
AI layer: compliance summary generation and document Q&A.

Privacy-by-design: the raw document NEVER leaves the machine. Every prompt
sent to the external LLM is built from the *redacted* text plus aggregate
finding metadata. Deterministic questions (counts, listings) are answered
locally from the detection results without any API call at all.

Works in two modes:
  - LLM mode: Google Gemini (set GEMINI_API_KEY) for narrative summaries
    and free-form Q&A.
  - Offline mode: a rule-based generator produces the compliance summary
    and Q&A from detection results, so the app is fully functional
    without any API key.
"""

from __future__ import annotations

import os
import re

from .detector import Finding, summarize_findings

_MAX_CONTEXT_CHARS = 24_000
_GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")

_gemini_client = None


def llm_available() -> bool:
    return bool(os.environ.get("GEMINI_API_KEY"))


def _get_client():
    global _gemini_client
    if _gemini_client is None:
        from google import genai
        _gemini_client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
    return _gemini_client


def _call_llm(prompt: str) -> str:
    response = _get_client().models.generate_content(
        model=_GEMINI_MODEL, contents=prompt,
    )
    return (response.text or "").strip()


# --------------------------------------------------------------------------
# Compliance summary
# --------------------------------------------------------------------------

_REMEDIATION = {
    "AADHAAR": "Mask or tokenize Aadhaar numbers; storing them in plain text "
               "violates the Aadhaar Act 2016 and DPDP Act 2023 requirements.",
    "PAN": "Restrict PAN storage to systems with a lawful purpose; encrypt at rest.",
    "CREDIT_CARD": "Card numbers must never be stored unmasked — PCI-DSS requires "
                   "truncation/tokenization and prohibits storing full PANs in documents.",
    "API_KEY": "Rotate the exposed keys immediately, move secrets to a vault "
               "(e.g. AWS Secrets Manager / HashiCorp Vault), and purge them from history.",
    "PASSWORD": "Rotate the exposed passwords immediately and remove them from the "
                "document; enforce a secrets-management policy.",
    "BANK_DETAILS": "Encrypt bank account details at rest and limit access to "
                    "finance/payroll roles only.",
    "EMAIL": "Personal email addresses are PII under DPDP/GDPR — share only on a "
             "need-to-know basis and honor deletion requests.",
    "PHONE": "Phone numbers are PII — mask in shared copies and restrict distribution.",
    "EMPLOYEE_ID": "Employee IDs enable correlation attacks when combined with "
                   "other identifiers; avoid publishing alongside PII.",
    "CONFIDENTIAL": "Apply a document classification label and distribute via "
                    "access-controlled channels only.",
}

_REGULATIONS = {
    "AADHAAR": "Aadhaar Act 2016, DPDP Act 2023",
    "PAN": "IT Act 2000, DPDP Act 2023",
    "CREDIT_CARD": "PCI-DSS, RBI data storage guidelines",
    "API_KEY": "ISO 27001 A.9 (access control), SOC 2",
    "PASSWORD": "ISO 27001 A.9, NIST 800-63B",
    "BANK_DETAILS": "RBI guidelines, DPDP Act 2023",
    "EMAIL": "DPDP Act 2023, GDPR Art. 4",
    "PHONE": "DPDP Act 2023, GDPR Art. 4",
    "EMPLOYEE_ID": "DPDP Act 2023 (indirect identifier)",
    "CONFIDENTIAL": "Contract/NDA obligations, ISO 27001 A.8",
}


def _rule_based_summary(findings: list[Finding], risk: dict, filename: str) -> str:
    agg = summarize_findings(findings)
    if not findings:
        return (
            f"**Compliance Summary — {filename}**\n\n"
            "No sensitive data was detected in this document. "
            "It is classified **Low Risk**. Standard information-handling "
            "practices apply; no remediation is required."
        )

    lines = [f"**Compliance Summary — {filename}**\n"]
    lines.append(f"**Overall classification: {risk['level']}** "
                 f"(risk score {risk['score']}, {risk['total_findings']} findings)\n")

    lines.append("**Compliance observations**")
    for label, info in sorted(agg.items(), key=lambda kv: -kv[1]["count"]):
        reg = _REGULATIONS.get(info["entity_type"], "internal policy")
        lines.append(f"- {info['count']}× {label} detected — regulated under {reg}.")

    lines.append("\n**Security risks**")
    seen_types = {info["entity_type"] for info in agg.values()}
    if {"API_KEY", "PASSWORD"} & seen_types:
        lines.append("- Exposed credentials allow direct unauthorized access to "
                     "systems; assume compromise until rotated.")
    if {"AADHAAR", "PAN", "CREDIT_CARD", "BANK_DETAILS"} & seen_types:
        lines.append("- Identity and financial data in combination enables "
                     "identity theft and financial fraud.")
    if {"EMAIL", "PHONE"} & seen_types:
        lines.append("- Contact details expose individuals to phishing and "
                     "social-engineering attacks.")
    if "CONFIDENTIAL" in seen_types:
        lines.append("- Confidential business language suggests this document "
                     "should not circulate outside its intended audience.")

    lines.append("\n**Suggested remediation steps**")
    added = set()
    for f in findings:
        if f.entity_type not in added and f.entity_type in _REMEDIATION:
            lines.append(f"- {_REMEDIATION[f.entity_type]}")
            added.add(f.entity_type)
    lines.append("- Record this scan in the audit trail and re-scan after remediation.")

    return "\n".join(lines)


def generate_summary(findings: list[Finding], risk: dict, redacted_text: str,
                     filename: str) -> tuple[str, str]:
    """Return (summary_markdown, mode) where mode is 'llm' or 'offline'."""
    baseline = _rule_based_summary(findings, risk, filename)
    if not llm_available():
        return baseline, "offline"

    agg = summarize_findings(findings)
    findings_desc = "\n".join(
        f"- {label}: {info['count']} occurrence(s), severity {info['severity']}"
        for label, info in agg.items()
    ) or "- none"

    prompt = f"""You are a data-protection compliance analyst. A document was scanned
by an automated sensitive-data detector. All sensitive values below are ALREADY
MASKED — never attempt to reconstruct them.

Document: {filename}
Risk classification: {risk['level']} (score {risk['score']})
Detected entities:
{findings_desc}

Redacted document excerpt:
---
{redacted_text[:_MAX_CONTEXT_CHARS]}
---

Write a concise compliance report in markdown with exactly these sections:
1. **Compliance observations** — which regulations apply (DPDP Act 2023, GDPR,
   PCI-DSS, Aadhaar Act, ISO 27001) and why, tied to the specific entities found.
2. **Security risks** — concrete attack scenarios these exposures enable.
3. **Suggested remediation steps** — prioritized, actionable steps.
Keep it under 350 words. Do not invent findings not listed above."""

    try:
        return _call_llm(prompt), "llm"
    except Exception:
        return baseline, "offline"


# --------------------------------------------------------------------------
# Question answering
# --------------------------------------------------------------------------

_COUNT_Q = re.compile(r"(?i)\bhow many\b|\bcount\b|\bnumber of\b")
_WHAT_SENSITIVE_Q = re.compile(r"(?i)sensitive|pii|personal data|what.*detect")
_RISK_Q = re.compile(r"(?i)\brisk|complian|regulat|violat|remediat")

_ENTITY_ALIASES = {
    "EMAIL": ["email", "e-mail", "mail address"],
    "PHONE": ["phone", "mobile", "contact number"],
    "AADHAAR": ["aadhaar", "aadhar", "uid"],
    "PAN": ["pan"],
    "CREDIT_CARD": ["credit card", "debit card", "card number"],
    "BANK_DETAILS": ["bank", "account number", "ifsc"],
    "API_KEY": ["api key", "token", "secret key"],
    "PASSWORD": ["password"],
    "EMPLOYEE_ID": ["employee id", "emp id", "staff id"],
    "CONFIDENTIAL": ["confidential"],
}


def _deterministic_answer(question: str, findings: list[Finding],
                          risk: dict) -> str | None:
    """Answer count/list/risk questions exactly from detection results."""
    q = question.lower()
    agg = summarize_findings(findings)

    if _COUNT_Q.search(q):
        for etype, aliases in _ENTITY_ALIASES.items():
            if any(a in q for a in aliases):
                n = sum(1 for f in findings if f.entity_type == etype)
                label = next((f.label for f in findings if f.entity_type == etype),
                             etype.replace("_", " ").title())
                return (f"**{n}** occurrence(s) of {label} detected."
                        if n else f"No {aliases[0]} entries were detected.")
        if "finding" in q or "sensitive" in q or "item" in q:
            return f"**{len(findings)}** sensitive findings in total across {len(agg)} categories."

    if _WHAT_SENSITIVE_Q.search(q) and ("what" in q or "which" in q or "list" in q):
        if not findings:
            return "No sensitive data was detected in this document."
        lines = ["The document contains the following sensitive data:"]
        for label, info in sorted(agg.items(), key=lambda kv: -kv[1]["count"]):
            ex = ", ".join(info["examples"])
            lines.append(f"- **{label}** — {info['count']}× (e.g. {ex})")
        return "\n".join(lines)

    if _RISK_Q.search(q) and not any(a in q for aliases in _ENTITY_ALIASES.values() for a in aliases):
        return (f"The document is classified **{risk['level']}** "
                f"(score {risk['score']}). {risk['explanation']}")

    return None


def answer_question(question: str, findings: list[Finding], risk: dict,
                    redacted_text: str, filename: str) -> tuple[str, str]:
    """Return (answer, mode) where mode is 'deterministic', 'llm' or 'offline'."""
    exact = _deterministic_answer(question, findings, risk)
    if exact is not None:
        return exact, "deterministic"

    if llm_available():
        agg = summarize_findings(findings)
        findings_desc = "\n".join(
            f"- {label}: {info['count']}×" for label, info in agg.items()
        ) or "- none"
        prompt = f"""You are a compliance assistant answering questions about a scanned
document. Sensitive values in the text below are ALREADY MASKED — never try to
guess or reconstruct them.

Document: {filename}
Risk level: {risk['level']} (score {risk['score']})
Detected sensitive entities:
{findings_desc}

Redacted document content:
---
{redacted_text[:_MAX_CONTEXT_CHARS]}
---

Question: {question}

Answer concisely from the document content and detection results above. If the
answer is not in the document, say so plainly."""
        try:
            return _call_llm(prompt), "llm"
        except Exception:
            pass

    # Offline fallback for open questions: structured digest.
    agg = summarize_findings(findings)
    lines = [
        "*(Offline mode — set GEMINI_API_KEY for free-form answers. "
        "Here is the document digest:)*",
        f"- Risk level: **{risk['level']}** (score {risk['score']})",
        f"- Total findings: {len(findings)}",
    ]
    for label, info in agg.items():
        lines.append(f"- {label}: {info['count']}×")
    return "\n".join(lines), "offline"
