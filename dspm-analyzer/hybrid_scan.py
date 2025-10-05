# -*- coding: utf-8 -*-
"""
hybrid_scan.py
Scan BOTH metadata and content for PII/sensitive info.
- Treat metadata as first-class content (it can leak PII)
- Use metadata risk as triage to choose scan depth for the data payload
- Optionally call Presidio ML (deep mode) when warranted
- Return a structured report suitable for storage/analytics
"""

import re, csv, io, json
from typing import Dict, List, Any, Tuple

# ========= 0) Patterns & Helpers =========

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?(?:0\d{1,2}|[2-9]\d{1,3})[-.\s]?\d{3,4}[-.\s]?\d{4}\b")
IPV4_RE  = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b")
CC_CANDIDATE_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
# KR Resident Registration Number-like (YYMMDD-1~4XXXXXX), simplified
RRN_RE = re.compile(r"(?<!\d)(\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])[-]?[1-4]\d{6}(?!\d)")

def luhn_valid(num: str) -> bool:
    s = re.sub(r"\D", "", num)
    if not (13 <= len(s) <= 19):
        return False
    tot, alt = 0, False
    for ch in reversed(s):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9: d -= 9
        tot += d
        alt = not alt
    return (tot % 10) == 0

# Header → canonical category
HEADER_MAP = {
    r"(^|_)name$": "NAME",
    r"(^|_)full_?name$": "NAME",
    r"(^|_)first_?name$": "NAME",
    r"(^|_)last_?name$": "NAME",
    r"(^|_)email$": "EMAIL_ADDRESS",
    r"(^|_)phone$": "PHONE_NUMBER",
    r"(^|_)mobile$": "PHONE_NUMBER",
    r"(^|_)address$": "LOCATION",
    r"(^|_)dob$": "DATE_TIME",
    r"(^|_)birth(_|)date$": "DATE_TIME",
    r"(^|_)gender$": "PERSONAL_ATTRIBUTE",
    r"(^|_)age$": "PERSONAL_ATTRIBUTE",
    r"(^|_)ip(_|)address$": "IP_ADDRESS",
    r"(^|_)id$": "ID_NUMBER",
    r"browsing_?history": "BEHAVIORAL_DATA",
    r"device_?type": "DEVICE_METADATA",
}

# Path tokens that hint “likely sensitive content” (triage only)
PATH_PII_HINTS = [
    "pii","private","confidential","secret",
    "user","users","customer","customers","client","clients","account",
    "passport","rrn","resident_registration","ssn","national_id","idcard",
    "health","medical","diagnosis","patient","pregnancy",
    "union","labor_union","political","belief","religion","sexual"
]

# ========= 1) Scanners =========

def scan_text_for_pii(s: str) -> Dict[str, int]:
    """Scan any text (metadata or content) for direct PII value matches."""
    hits: Dict[str, int] = {}
    if not s:
        return hits
    for _ in EMAIL_RE.finditer(s): hits["EMAIL_ADDRESS"] = hits.get("EMAIL_ADDRESS", 0) + 1
    for _ in IPV4_RE.finditer(s):  hits["IP_ADDRESS"]     = hits.get("IP_ADDRESS", 0) + 1
    for _ in PHONE_RE.finditer(s): hits["PHONE_NUMBER"]   = hits.get("PHONE_NUMBER", 0) + 1
    for m in CC_CANDIDATE_RE.finditer(s):
        if luhn_valid(m.group(0)): hits["CREDIT_CARD"]    = hits.get("CREDIT_CARD", 0) + 1
    for _ in RRN_RE.finditer(s):   hits["ID_NUMBER_RRN_LIKE"] = hits.get("ID_NUMBER_RRN_LIKE", 0) + 1
    return hits

def scan_all_metadata(blob: Dict[str, Any]) -> Dict[str, int]:
    """
    Treat metadata as content & scan it for PII. Also add RISK_HINTS_IN_PATH for triage.
    """
    meta_hits: Dict[str, int] = {}

    def merge(d: Dict[str, int]):
        for k, v in d.items():
            meta_hits[k] = meta_hits.get(k, 0) + v

    key = str(blob.get("key", ""))
    merge(scan_text_for_pii(key))
    merge(scan_text_for_pii(str(blob.get("last_modified", ""))))
    merge(scan_text_for_pii(str(blob.get("size", ""))))

    # Optional user metadata/tags/labels
    for field in ("metadata", "tags", "labels"):
        md = blob.get(field)
        if isinstance(md, dict):
            for mk, mv in md.items():
                merge(scan_text_for_pii(str(mk)))
                merge(scan_text_for_pii(str(mv)))

    # Triage-only hints
    hint_count = sum(1 for kw in PATH_PII_HINTS if kw in key.lower())
    if hint_count:
        meta_hits["RISK_HINTS_IN_PATH"] = hint_count
    return meta_hits

def categorize_header(colname: str) -> List[str]:
    cats: List[str] = []
    c = colname.strip().lower()
    for patt, label in HEADER_MAP.items():
        if re.search(patt, c):
            cats.append(label)
    return sorted(set(cats))

def scan_value_categories(val: str) -> List[str]:
    """Return canonical categories that appear inside a single cell value."""
    cats: List[str] = []
    if EMAIL_RE.search(val): cats.append("EMAIL_ADDRESS")
    if IPV4_RE.search(val):  cats.append("IP_ADDRESS")
    if PHONE_RE.search(val): cats.append("PHONE_NUMBER")
    for m in CC_CANDIDATE_RE.finditer(val):
        if luhn_valid(m.group(0)): cats.append("CREDIT_CARD")
    if RRN_RE.search(val):   cats.append("ID_NUMBER_RRN_LIKE")
    return sorted(set(cats))

def detect_in_csv_text(text: str) -> Dict[str, Any]:
    """
    CSV scanner:
    - header categories (schema signal)
    - value categories (cell content)
    """
    f = io.StringIO(text)
    reader = csv.DictReader(f)
    headers = reader.fieldnames or []

    header_summary: Dict[str, List[str]] = {h: categorize_header(h) for h in headers}

    value_summary: Dict[str, int] = {}
    per_column_counts: Dict[Tuple[str, str], int] = {}
    rows_scanned = 0

    for row in reader:
        rows_scanned += 1
        for col, raw in row.items():
            if not raw:
                continue
            cats = scan_value_categories(str(raw))
            for c in cats:
                value_summary[c] = value_summary.get(c, 0) + 1
                per_column_counts[(col, c)] = per_column_counts.get((col, c), 0) + 1

    per_column = []
    for h in headers:
        per_column.append({
            "column": h,
            "header_categories": header_summary.get(h, []),
            "value_categories": {cat: cnt for (col, cat), cnt in per_column_counts.items() if col == h}
        })

    return {
        "rows_scanned": rows_scanned,
        "header_summary": header_summary,
        "value_summary": value_summary,
        "per_column": per_column,
    }

def walk_json(obj: Any) -> Dict[str, int]:
    """Generic JSON walker: header-like key scan + value scan."""
    hits: Dict[str, int] = {}
    def bump(cat): hits[cat] = hits.get(cat, 0) + 1

    if isinstance(obj, dict):
        for k, v in obj.items():
            for cat in categorize_header(str(k)): bump(cat)
            if isinstance(v, (str, int, float)):
                for cat in scan_value_categories(str(v)): bump(cat)
            else:
                sub = walk_json(v)
                for c, n in sub.items(): hits[c] = hits.get(c, 0) + n
    elif isinstance(obj, list):
        for v in obj:
            sub = walk_json(v)
            for c, n in sub.items(): hits[c] = hits.get(c, 0) + n
    else:
        if isinstance(obj, (str, int, float)):
            for cat in scan_value_categories(str(obj)): bump(cat)
    return hits

# ========= 2) Scan-depth policy (triage) =========

def choose_scan_mode(meta_hits: Dict[str, int]) -> str:
    """
    Decide scan depth from metadata signals.
    - 'deep'     : metadata already contains PII (email/phone/rrn/cc/ip)
    - 'standard' : path contains risk hint tokens
    - 'fast'     : otherwise
    """
    pii_keys = {"EMAIL_ADDRESS","PHONE_NUMBER","ID_NUMBER_RRN_LIKE","CREDIT_CARD","IP_ADDRESS"}
    if any(k in meta_hits for k in pii_keys):
        return "deep"
    if meta_hits.get("RISK_HINTS_IN_PATH", 0) > 0:
        return "standard"
    return "fast"

# ========= 3) Orchestrator =========

def analyze_payload(blobs: List[Dict[str, Any]], use_deep: bool = True) -> List[Dict[str, Any]]:
    # Lazy import so script works even if Presidio deps aren’t installed
    deep_scan_text = None
    if use_deep:
        try:
            from deep_mode import deep_scan_text as _deep
            deep_scan_text = _deep
        except Exception:
            deep_scan_text = None  # deep unavailable; proceed without ML

    reports: List[Dict[str, Any]] = []

    for blob in blobs:
        # (A) Metadata as content
        meta_pii = scan_all_metadata(blob)
        mode = choose_scan_mode(meta_pii)

        key = blob.get("key", "")
        size = blob.get("size")
        last_modified = blob.get("last_modified")
        content = blob.get("content", {})

        report: Dict[str, Any] = {
            "key": key,
            "size": size,
            "last_modified": last_modified,
            "content_type": None,
            "scan_mode": mode,
            "metadata_pii": meta_pii,   # concrete PII found in metadata + risk hints
            "rows_scanned": 0,
            "columns": [],
            "findings": {},
        }

        # (B) Content scan (depth chosen by metadata)
        text = content.get("text")
        metrics = content.get("metrics")

        if text is not None:
            # CSV vs plain text
            header_line = text.split("\n", 1)[0]
            report["content_type"] = "text/csv" if header_line.count(",") >= 1 else "text/plain"

            if report["content_type"] == "text/csv":
                csv_res = detect_in_csv_text(text if mode != "fast" else "\n".join(text.splitlines()[:200]))
                report["rows_scanned"] = csv_res["rows_scanned"]
                report["columns"] = csv_res["per_column"]
                report["findings"] = {
                    "headers": csv_res["header_summary"],
                    "values": csv_res["value_summary"],
                }
            else:
                report["findings"] = {"values_in_text": scan_text_for_pii(text)}
                if deep_scan_text and mode in ("standard", "deep"):
                    try:
                        d = deep_scan_text(text)
                        report["findings"]["deep"] = d.get("merged", [])
                    except Exception:
                        report["findings"]["deep"] = []

            # Deep mode (Presidio ML + your custom recognizers) if available & warranted
            # inside analyze_payload(...) after building report["findings"] for CSV:
            if deep_scan_text and mode in ("standard", "deep"):
                # Build per-row blobs to give recognizers clean sentences
                f = io.StringIO(text)
                reader = csv.DictReader(f)
                deep_hits = []
                for row in reader:
                    blob = " | ".join(f"{k}: {v}" for k, v in row.items() if v)
                    if not blob:
                        continue
                    try:
                        d = deep_scan_text(blob)            # dict
                        deep_hits.extend(d.get("merged", []))  # <- merged만 누적
                    except Exception:
                        pass
                report["findings"]["deep"] = deep_hits

        elif metrics is not None:
            report["content_type"] = "application/json"
            report["findings"] = {"json_values": walk_json(metrics)}

            # Optional deep scan on flattened JSON
            if deep_scan_text and mode in ("standard", "deep"):
                flat_texts: List[str] = []
                def walk(o):
                    if isinstance(o, dict):
                        for k, v in o.items():
                            if isinstance(v, (str, int, float)):
                                flat_texts.append(f"{k}: {v}")
                            else:
                                walk(v)
                    elif isinstance(o, list):
                        for v in o:
                            walk(v)
                walk(metrics)
                if flat_texts:
                    try:
                        d = deep_scan_text(" | ".join(flat_texts))
                        report["findings"]["deep"] = d.get("merged", [])
                    except Exception:
                        report["findings"]["deep"] = []

        else:
            report["content_type"] = "unknown"

        reports.append(report)

    return reports

# ========= 4) CLI =========

if __name__ == "__main__":
    import argparse
    from pathlib import Path

    parser = argparse.ArgumentParser(description="Hybrid PII/Sensitive scanner")
    parser.add_argument("--input", "-i",
                        default=str(Path(__file__).parent / "sample_payload.json"),
                        help="Path to payload JSON (list of blobs). Default: sample_payload.json next to this script.")
    parser.add_argument("--save", "-o", default="",
                        help="Optional: path to save full results JSON (e.g., results.json).")
    parser.add_argument("--no-deep", action="store_true",
                        help="Disable deep (Presidio ML) scan even if available.")
    args = parser.parse_args()

    payload_path = Path(args.input)
    if not payload_path.exists():
        raise SystemExit(f"[!] Cannot find payload file: {payload_path}\n"
                         f"Create it and paste your dummy JSON there.")
    payload = json.loads(payload_path.read_text(encoding="utf-8"))

    reports = analyze_payload(payload, use_deep=not args.no_deep)
    print(json.dumps(reports, ensure_ascii=False, indent=2))

    if args.save:
        Path(args.save).write_text(json.dumps(reports, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\nSaved full results to: {Path(args.save).resolve()}")
