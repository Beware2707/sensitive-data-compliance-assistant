"""Document-level risk classification from detection findings."""

from __future__ import annotations

from .detector import Finding

# Score thresholds for the overall document classification.
HIGH_THRESHOLD = 15
MEDIUM_THRESHOLD = 5

# Any single finding of these types immediately makes the document High Risk:
# a leaked credential or a government identity number is critical regardless
# of how clean the rest of the document is.
CRITICAL_TYPES = {"AADHAAR", "CREDIT_CARD", "API_KEY", "PASSWORD"}

RISK_EXPLANATIONS = {
    "High Risk": "Contains critical identifiers or credentials (Aadhaar, cards, "
                 "API keys/passwords) or a large volume of sensitive data. "
                 "Immediate remediation recommended.",
    "Medium Risk": "Contains personal contact data or financial/business "
                   "references. Should be access-controlled and reviewed.",
    "Low Risk": "Little or no sensitive data detected. Standard data-handling "
                "practices are sufficient.",
}


def classify(findings: list[Finding]) -> dict:
    """Return risk level, numeric score, and per-severity breakdown."""
    score = sum(f.weight for f in findings)
    has_critical = any(f.entity_type in CRITICAL_TYPES for f in findings)

    if has_critical or score >= HIGH_THRESHOLD:
        level = "High Risk"
    elif score >= MEDIUM_THRESHOLD:
        level = "Medium Risk"
    else:
        level = "Low Risk"

    by_severity = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        by_severity[f.severity] += 1

    return {
        "level": level,
        "score": score,
        "total_findings": len(findings),
        "by_severity": by_severity,
        "has_critical": has_critical,
        "explanation": RISK_EXPLANATIONS[level],
    }
