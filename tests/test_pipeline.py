"""End-to-end tests for the detection, risk, redaction and Q&A pipeline.

Run with:  python -m pytest tests/ -v   (or plain: python tests/test_pipeline.py)
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ai_engine import answer_question, generate_summary
from src.detector import detect, luhn_valid, verhoeff_valid
from src.extractor import extract_text
from src.redactor import redact_text
from src.risk import classify

SAMPLE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "sample_docs")


def _types(findings):
    return {f.entity_type for f in findings}


def test_checksums():
    assert verhoeff_valid("234567890124")
    assert not verhoeff_valid("234567890123")
    assert luhn_valid("4111111111111111")
    assert not luhn_valid("4111111111111112")


def test_detects_all_entity_classes():
    with open(os.path.join(SAMPLE_DIR, "sample_confidential_report.txt"), "rb") as fh:
        text = extract_text(fh.read(), "sample_confidential_report.txt")
    findings = detect(text)
    found = _types(findings)
    for expected in ["AADHAAR", "PAN", "EMAIL", "PHONE", "CREDIT_CARD",
                     "BANK_DETAILS", "API_KEY", "PASSWORD", "EMPLOYEE_ID",
                     "CONFIDENTIAL"]:
        assert expected in found, f"missing {expected}; found={found}"


def test_high_risk_classification():
    with open(os.path.join(SAMPLE_DIR, "sample_confidential_report.txt"), "rb") as fh:
        text = extract_text(fh.read(), "x.txt")
    risk = classify(detect(text))
    assert risk["level"] == "High Risk"


def test_clean_document_is_low_risk():
    with open(os.path.join(SAMPLE_DIR, "sample_meeting_notes.txt"), "rb") as fh:
        text = extract_text(fh.read(), "x.txt")
    findings = detect(text)
    risk = classify(findings)
    assert risk["level"] == "Low Risk", (risk, [(f.label, f.value) for f in findings])


def test_csv_extraction_and_detection():
    with open(os.path.join(SAMPLE_DIR, "sample_hr_data.csv"), "rb") as fh:
        text = extract_text(fh.read(), "sample_hr_data.csv")
    findings = detect(text)
    found = _types(findings)
    assert {"AADHAAR", "PAN", "EMAIL", "PHONE", "BANK_DETAILS", "EMPLOYEE_ID"} <= found
    emails = [f for f in findings if f.entity_type == "EMAIL"]
    assert len(emails) == 3


def test_redaction_removes_raw_values():
    text = "Contact rakesh.sharma@corp.example.com, card 4111 1111 1111 1111."
    findings = detect(text)
    masked = redact_text(text, findings, mode="mask")
    redacted = redact_text(text, findings, mode="redact")
    assert "rakesh.sharma@corp.example.com" not in masked
    assert "4111 1111 1111 1111" not in masked
    assert "[CREDIT_CARD]" in redacted and "[EMAIL]" in redacted


def test_false_positive_resistance():
    # Invalid checksums and bare numbers with no context should NOT match.
    text = ("Order id 123456789872 was shipped. Invoice total 4111111111111112. "
            "Ref 2345 6789 0123 attached. The build took 9876543210 ms.")
    findings = detect(text)
    assert "CREDIT_CARD" not in _types(findings)
    assert "AADHAAR" not in _types(findings)
    assert "BANK_DETAILS" not in _types(findings)


def test_deterministic_qa():
    with open(os.path.join(SAMPLE_DIR, "sample_hr_data.csv"), "rb") as fh:
        text = extract_text(fh.read(), "hr.csv")
    findings = detect(text)
    risk = classify(findings)
    masked = redact_text(text, findings)

    ans, mode = answer_question("How many email addresses are present?",
                                findings, risk, masked, "hr.csv")
    assert mode == "deterministic" and "3" in ans

    ans, mode = answer_question("What sensitive data exists in the document?",
                                findings, risk, masked, "hr.csv")
    assert mode == "deterministic" and "Aadhaar" in ans

    ans, mode = answer_question("What compliance risks are identified?",
                                findings, risk, masked, "hr.csv")
    assert mode == "deterministic" and "High Risk" in ans


def test_offline_summary():
    with open(os.path.join(SAMPLE_DIR, "sample_confidential_report.txt"), "rb") as fh:
        text = extract_text(fh.read(), "report.txt")
    findings = detect(text)
    risk = classify(findings)
    masked = redact_text(text, findings)
    summary, mode = generate_summary(findings, risk, masked, "report.txt")
    assert "remediation" in summary.lower()
    assert "High Risk" in summary


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS  {name}")
            except AssertionError as exc:
                failures += 1
                print(f"FAIL  {name}: {exc}")
    sys.exit(1 if failures else 0)
