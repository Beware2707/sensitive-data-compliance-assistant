# 🛡️ Sensitive Data Detection & Compliance Assistant

An AI-powered application that scans uploaded documents (PDF / TXT / CSV) for
sensitive and confidential information, classifies the document's risk level,
generates a compliance report with remediation steps, and answers natural-language
questions about the document.

> **Repository:** https://github.com/Beware2707/sensitive-data-compliance-assistant
> **Live demo:** https://jay-sensitive-data-compliance-assistant.streamlit.app
> **Demo video:** https://github.com/Beware2707/sensitive-data-compliance-assistant/blob/main/20260702_225811.mp4

---

## ✨ Features

| Requirement | Status |
|---|---|
| Upload PDF / TXT / CSV | ✅ |
| Detect Aadhaar, PAN, emails, phones, credit cards, bank details, API keys/passwords, employee IDs, confidential business terms | ✅ (10 entity classes) |
| Risk classification (Low / Medium / High) | ✅ weighted scoring + critical-entity override |
| AI compliance summary (observations, risks, remediation) | ✅ Gemini + offline rule-engine fallback |
| Question answering about the document | ✅ hybrid deterministic + LLM |
| **Bonus:** data masking / redaction | ✅ partial masking + full redaction, downloadable |
| **Bonus:** multi-document support | ✅ upload many, per-document analysis + overview table |
| **Bonus:** audit logging | ✅ append-only JSONL with SHA-256 file hashes |
| **Bonus:** Dockerization | ✅ `Dockerfile` included |
| **Bonus:** dashboard UI | ✅ metrics, severity breakdown, tabbed views |

## 🚀 Setup instructions

### Local (recommended for development)

```bash
git clone https://github.com/Beware2707/sensitive-data-compliance-assistant.git
cd sensitive-data-compliance-assistant
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
streamlit run app.py
```

Open http://localhost:8501 and upload a file from `sample_docs/`.

### Enable AI mode (optional but recommended)

The app is **fully functional without any API key** — a built-in rule engine
generates summaries and answers count/list/risk questions exactly. To enable
LLM-written narratives and free-form Q&A, set a (free-tier) Gemini key:

```bash
# Windows PowerShell
$env:GEMINI_API_KEY = "your-key"
# macOS/Linux
export GEMINI_API_KEY="your-key"
```

Get a key at https://aistudio.google.com/apikey.

### Docker

```bash
docker build -t compliance-assistant .
docker run -p 8501:8501 -e GEMINI_API_KEY=your-key compliance-assistant
```

### Run tests

```bash
python tests/test_pipeline.py        # zero-dependency runner
# or: python -m pytest tests/ -v
```

## 🏗️ Architecture overview

```
┌────────────────────────────  Streamlit UI (app.py)  ───────────────────────────┐
│  upload → dashboard (metrics/tabs) → redacted download → chat Q&A → audit view │
└───────┬─────────────────────────────────────────────────────────────┬──────────┘
        │                                                             │
        ▼                                                             ▼
┌──────────────────┐   ┌──────────────────┐   ┌──────────────┐  ┌──────────────┐
│  extractor.py    │──▶│   detector.py    │──▶│   risk.py    │  │   audit.py   │
│  PDF (pypdf)     │   │ regex candidates │   │ weighted     │  │ JSONL log,   │
│  CSV (pandas,    │   │ + checksum       │   │ score +      │  │ SHA-256 file │
│   labeled rows)  │   │   validation     │   │ critical-    │  │ hashes,      │
│  TXT (multi-     │   │ + context-window │   │ entity       │  │ metadata     │
│   encoding)      │   │   scoring        │   │ override     │  │ only         │
└──────────────────┘   └────────┬─────────┘   └──────┬───────┘  └──────────────┘
                                │                    │
                                ▼                    ▼
                       ┌──────────────────┐  ┌─────────────────────────────┐
                       │   redactor.py    │─▶│        ai_engine.py         │
                       │ mask / redact by │  │ deterministic Q&A (local)   │
                       │ finding offsets  │  │ + Gemini on REDACTED text   │
                       └──────────────────┘  │ + offline rule-based mode   │
                                             └─────────────────────────────┘
```

**Pipeline:** every upload flows through extract → detect → classify → redact →
summarize, and the results are cached in session state. The Q&A layer works on
the cached findings and the *redacted* text only.

**Key design decision — privacy by design:** the raw document **never leaves
the machine**. Prompts sent to the external LLM are built exclusively from the
redacted text plus aggregate finding counts. A compliance tool that leaked the
very PII it detects to a third-party API would defeat its own purpose.

## 🤖 AI/ML approach used

A **hybrid neuro-symbolic pipeline** — deterministic where precision matters,
generative where language matters:

1. **Detection (symbolic, high precision).** Regex produces candidates; each
   candidate must then survive validation:
   - **Aadhaar** → Verhoeff checksum (the actual UIDAI algorithm) — a random
     12-digit number has only a 10% chance of passing.
   - **Credit cards** → Luhn mod-10 checksum + issuer-prefix check.
   - **PAN** → structural rule (4th character encodes holder type).
   - **Bank accounts, phones, employee IDs** → context-window scoring: a bare
     digit run only counts if banking/contact/HR keywords appear within ±60
     characters. CSV extraction renders rows as `column: value` pairs so
     column names feed this context scoring.
   This layered approach is why the test suite includes an explicit
   **false-positive resistance test** (invalid checksums and context-free
   numbers must NOT match).

2. **Risk classification (explainable scoring).** Each finding carries a
   severity weight (API key = 10, PAN = 8, email = 3 …). Document score
   thresholds give Low/Medium/High, with an override: *any single* critical
   entity (Aadhaar, card, credential) forces High Risk — one leaked API key is
   critical no matter how clean the rest of the document is. Fully explainable
   — the UI shows exactly what contributed.

3. **Generation (LLM with grounding).** Gemini (`gemini-2.0-flash`) writes the
   compliance narrative and answers open questions. The prompt is grounded
   with the structured detection results and *redacted* text and explicitly
   instructed not to invent findings — the deterministic layer acts as a
   hallucination guard.

4. **Hybrid Q&A routing.** Questions like *"how many email addresses?"* are
   intent-matched and answered **exactly** from detection results (an LLM
   counting entities is unreliable); open questions like *"summarize this
   document"* route to the LLM. Every answer is labeled with its source
   (`deterministic` / `llm` / `offline`).

5. **Graceful degradation.** With no API key (or an API failure), a rule-based
   generator produces the full compliance report — mapped to real regulations
   (DPDP Act 2023, Aadhaar Act 2016, PCI-DSS, GDPR, ISO 27001) — so the app
   never has a hard dependency on an external service.

## 🧗 Challenges faced

1. **False positives on numeric data.** Any 12-digit number looks like an
   Aadhaar; invoice/order IDs look like accounts. Solved with checksum
   validation (Verhoeff/Luhn) plus context-window keyword gating — and locked
   in with a dedicated false-positive regression test.
2. **Overlapping matches.** An Aadhaar number is also a valid phone-length
   digit run; a `sk-…` key also matches the generic secret pattern. Solved
   with span-claiming: detectors run in confidence order and later detectors
   skip already-claimed spans.
3. **Sending sensitive data to an LLM.** The core tension of an AI compliance
   tool. Solved by redacting *before* prompting and answering counting
   questions locally without any API call.
4. **Secrets in identifiers.** `db_password = …` doesn't match `\bpassword` —
   word boundaries don't fire after `_`. Caught by the test suite; fixed by
   allowing prefixed identifiers.
5. **CSV context loss.** Flattening a CSV to plain text loses the column
   semantics the context scorer needs. Solved by rendering each row as
   `column: value` pairs so headers sit adjacent to values.
6. **Working offline.** Evaluators may not have an API key handy, so the
   rule-based fallback produces the complete report regardless.

## 🔮 Future improvements

- **OCR** (Tesseract / `pytesseract`) for scanned PDFs and images.
- **NER models** (spaCy / HuggingFace) to catch person names and addresses that
  regex can't, fused with the regex layer.
- **True RAG**: chunk + embed documents (FAISS/ChromaDB) for Q&A over very
  large documents instead of truncated context.
- **Redacted PDF export** preserving original layout.
- **User accounts & RBAC** so audit logs are attributable.
- **Policy packs**: configurable detection rules per regulation (GDPR vs DPDP
  vs HIPAA profiles).
- **Batch/API mode**: a FastAPI endpoint for CI-pipeline scanning of documents
  before they are shared.

## 📁 Project structure

```
├── app.py                  # Streamlit UI
├── src/
│   ├── extractor.py        # PDF/TXT/CSV → text
│   ├── detector.py         # detection engine (regex + checksums + context)
│   ├── risk.py             # risk scoring & classification
│   ├── redactor.py         # masking / redaction
│   ├── ai_engine.py        # Gemini summary & Q&A + offline fallback
│   └── audit.py            # JSONL audit trail
├── tests/test_pipeline.py  # 9 end-to-end tests
├── sample_docs/            # synthetic demo documents (safe test data)
├── Dockerfile
└── requirements.txt
```

## Deployment

**Streamlit Community Cloud (free):**
1. Push this repo to GitHub.
2. Go to https://share.streamlit.io → *New app* → pick the repo, branch `main`, file `app.py`.
3. In *Advanced settings → Secrets*, add `GEMINI_API_KEY = "your-key"` (optional).
4. Deploy — you get a public `https://<app>.streamlit.app` URL to submit.

**Note on sample data:** all identifiers in `sample_docs/` are synthetic.
Card numbers are industry-standard test numbers; Aadhaar-style numbers are
generated to pass the Verhoeff checksum but are not real UIDs.
