"""Text extraction for PDF / TXT / CSV uploads."""

from __future__ import annotations

import io

import pandas as pd
from pypdf import PdfReader

SUPPORTED_EXTENSIONS = {".pdf", ".txt", ".csv"}


class ExtractionError(Exception):
    pass


def extract_text(file_bytes: bytes, filename: str) -> str:
    """Return plain text from an uploaded file, dispatching on extension."""
    name = filename.lower()
    if name.endswith(".pdf"):
        return _extract_pdf(file_bytes)
    if name.endswith(".csv"):
        return _extract_csv(file_bytes)
    if name.endswith(".txt"):
        return _extract_txt(file_bytes)
    raise ExtractionError(f"Unsupported file type: {filename}")


def _extract_pdf(file_bytes: bytes) -> str:
    try:
        reader = PdfReader(io.BytesIO(file_bytes))
    except Exception as exc:
        raise ExtractionError(f"Could not open PDF: {exc}") from exc
    if reader.is_encrypted:
        try:
            reader.decrypt("")
        except Exception as exc:
            raise ExtractionError("PDF is password-protected.") from exc
    pages = []
    for i, page in enumerate(reader.pages, start=1):
        text = page.extract_text() or ""
        pages.append(f"[Page {i}]\n{text}")
    combined = "\n\n".join(pages)
    if not combined.replace("[Page", "").strip("] 0123456789\n"):
        raise ExtractionError(
            "No extractable text found — this PDF appears to be scanned images. "
            "OCR is not enabled in this deployment."
        )
    return combined


def _extract_csv(file_bytes: bytes) -> str:
    for encoding in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            df = pd.read_csv(io.BytesIO(file_bytes), encoding=encoding, dtype=str)
            break
        except UnicodeDecodeError:
            continue
        except Exception as exc:
            raise ExtractionError(f"Could not parse CSV: {exc}") from exc
    else:
        raise ExtractionError("Could not decode CSV file.")
    # Render as labeled rows so column context sits next to each value —
    # the detector's context-window scoring depends on this.
    lines = [f"CSV columns: {', '.join(df.columns)}"]
    for idx, row in df.iterrows():
        cells = [f"{col}: {val}" for col, val in row.items() if pd.notna(val)]
        lines.append(f"Row {idx + 1} | " + " | ".join(cells))
    return "\n".join(lines)


def _extract_txt(file_bytes: bytes) -> str:
    for encoding in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return file_bytes.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise ExtractionError("Could not decode text file.")
