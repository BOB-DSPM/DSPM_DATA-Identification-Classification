# -*- coding: utf-8 -*-
import os, re, io, csv, json
from pathlib import Path
from typing import Dict, List, Any, Tuple

# =========================================================
# 0) 실행 로그: Presidio 항상 시도 (성공/실패 로그 출력)
# =========================================================
ENGINE_PII_AVAILABLE = False
try:
    from engine_pii import analyze_text as _presidio_analyze_text
    from engine_pii import list_loaded_recognizers as _presidio_list_loaded
    ENGINE_PII_AVAILABLE = True
    print("[info] Presidio: ON (engine_pii.analyze_text 사용)")
except Exception as e:
    print(f"[warn] Presidio import 실패: {e}  -> Presidio 결과는 비게 나올 수 있습니다.")

# (선택) 시작 시 자가 테스트: 한국어 민감어가 실제로 매칭되는지 확인
if ENGINE_PII_AVAILABLE and os.getenv("PRESIDIO_SELFTEST", "0") == "1":
    try:
        sample = "성생활 관련 상담 이력과 임신 기록은 민감정보입니다. 정치적 견해, 노동조합 가입도 포함."
        demo = _presidio_analyze_text(sample)
        print("[selftest] recognizers:", _presidio_list_loaded())
        print("[selftest] hits:", [(h["entity"], h["text"]) for h in demo.get("merged", [])])
    except Exception as e:
        print(f"[selftest] 실패: {e}")

# 카드번호를 민감정보로 '격상'할지 여부
TREAT_CREDIT_CARD_AS_SENSITIVE = bool(int(os.getenv("TREAT_CREDIT_CARD_AS_SENSITIVE", "0")))

# =========================================================
# 1) 정규식 패턴 (전화번호 과탐 완화)
# =========================================================
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
IPV4_RE  = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b")
CC_CANDIDATE_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
RRN_RE = re.compile(r"(?<!\d)(\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])[-]?[1-4]\d{6}(?!\d)")

PHONE_RE = re.compile(
    r"(?<!\d)"
    r"(?:\+?82[-.\s]?)?"
    r"(?:0?(?:10|11|16|17|18|19|2|3[1-3]|4[1-4]|5[1-5]|6[1-4]))"
    r"[-.\s]?\d{3,4}[-.\s]?\d{4}"
    r"(?!\d)"
)

# 라우팅 판단용 엔티티 세트
ID_ENTS = {"KR_RRN","KR_FRN","KR_PASSPORT","KR_DRIVER_LICENSE"}
PIPA_ENTS = {
    "KOREAN_PIPA_POLITICAL","KOREAN_PIPA_UNION","KOREAN_PIPA_HEALTH",
    "KOREAN_PIPA_SEX_LIFE","KOREAN_PIPA_BELIEF"
}
GENERAL_PII = {"EMAIL_ADDRESS","PHONE_NUMBER","IP_ADDRESS","CREDIT_CARD","ID_NUMBER_RRN_LIKE"}

# 파일 경로 위험 힌트(분류 보조)
HINTS_SENSITIVE   = ["political","union","religion","belief","sex","health","medical","diagnosis","patient","pregnancy"]
HINTS_IDENTIFIERS = ["passport","rrn","resident_registration","driver","license","idcard","national_id","ssn"]
HINTS_PII         = ["pii","private","confidential","secret","customer","user","account"]

CLASSIFY_ROOT = "classified"

# =========================================================
# 2) 유틸
# =========================================================
def luhn_valid(num: str) -> bool:
    s = re.sub(r"\D", "", num)
    if not (13 <= len(s) <= 19): return False
    tot, alt = 0, False
    for ch in reversed(s):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9: d -= 9
        tot += d
        alt = not alt
    return (tot % 10) == 0

def ensure_list(d: Dict[str, List[str]], key: str):
    if key not in d: d[key] = []

def _spans(pattern: re.Pattern, s: str) -> List[Tuple[int,int]]:
    return [(m.start(), m.end()) for m in pattern.finditer(s)]

def _overlap(a: Tuple[int,int], b: Tuple[int,int]) -> bool:
    return not (a[1] <= b[0] or b[1] <= a[0])

def _digits_len(s: str) -> int:
    return len(re.sub(r"\D", "", s))

def _is_plausible_kr_phone(raw: str) -> bool:
    dlen = _digits_len(raw)
    if not (9 <= dlen <= 11): return False
    if "0000" in raw: return False
    return True

# =========================================================
# 3) 텍스트 스캔
# =========================================================
def scan_text_values_all(s: str) -> Dict[str, List[str]]:
    vals: Dict[str, List[str]] = {}
    if not s:
        return vals

    rrn_spans = _spans(RRN_RE, s)
    cc_spans  = _spans(CC_CANDIDATE_RE, s)

    for m in EMAIL_RE.finditer(s):
        ensure_list(vals,"EMAIL_ADDRESS"); vals["EMAIL_ADDRESS"].append(m.group(0))

    for m in IPV4_RE.finditer(s):
        ensure_list(vals,"IP_ADDRESS"); vals["IP_ADDRESS"].append(m.group(0))

    for m in CC_CANDIDATE_RE.finditer(s):
        raw = m.group(0)
        if luhn_valid(raw):
            ensure_list(vals,"CREDIT_CARD"); vals["CREDIT_CARD"].append(raw)

    for m in RRN_RE.finditer(s):
        ensure_list(vals,"ID_NUMBER_RRN_LIKE"); vals["ID_NUMBER_RRN_LIKE"].append(m.group(0))

    for m in PHONE_RE.finditer(s):
        span = (m.start(), m.end())
        if any(_overlap(span, r) for r in rrn_spans):  # 주민번호와 겹치면 제외
            continue
        if any(_overlap(span, c) for c in cc_spans):   # 카드와 겹치면 제외
            continue
        raw = m.group(0)
        if not _is_plausible_kr_phone(raw):
            continue
        ensure_list(vals,"PHONE_NUMBER"); vals["PHONE_NUMBER"].append(raw)

    return {k: list(dict.fromkeys(v)) for k,v in vals.items()}

# =========================================================
# 4) 메타데이터 스캔
# =========================================================
def scan_metadata(blob: Dict[str,Any]) -> Dict[str,Any]:
    key = str(blob.get("key",""))
    vals: Dict[str, List[str]] = {}

    for field in ("key","last_modified","size"):
        found = scan_text_values_all(str(blob.get(field,"")))
        for k, arr in found.items():
            ensure_list(vals,k); vals[k].extend(arr)

    for field in ("metadata","tags","labels"):
        md = blob.get(field)
        if isinstance(md, dict):
            for mk, mv in md.items():
                for k, arr in scan_text_values_all(str(mk)).items():
                    ensure_list(vals,k); vals[k].extend(arr)
                for k, arr in scan_text_values_all(str(mv)).items():
                    ensure_list(vals,k); vals[k].extend(arr)

    matched = []
    lowered = key.lower()
    for t in set(HINTS_SENSITIVE + HINTS_IDENTIFIERS + HINTS_PII):
        if t in lowered: matched.append(t)

    return {
        "values": {k: list(dict.fromkeys(v)) for k,v in vals.items()},
        "risk_hints": {"count": len(matched), "matched": matched}
    }

# =========================================================
# 5) 본문 스캔
# =========================================================
def detect_in_csv_text(text: str) -> Dict[str, Any]:
    f = io.StringIO(text)
    reader = csv.DictReader(f)
    values: Dict[str, List[str]] = {}
    rows_scanned = 0
    for row in reader:
        rows_scanned += 1
        for _, raw in row.items():
            if not raw: continue
            for k, arr in scan_text_values_all(str(raw)).items():
                ensure_list(values,k); values[k].extend(arr)
    values = {k: list(dict.fromkeys(v)) for k,v in values.items()}
    return {"rows_scanned": rows_scanned, "values_text": values}

def detect_in_plain_text(text: str) -> Dict[str, Any]:
    return {"values": scan_text_values_all(text)}

def detect_in_json(obj: Any) -> Dict[str, List[str]]:
    vals: Dict[str, List[str]] = {}
    def bump(cat, v): ensure_list(vals,cat); vals[cat].append(v)
    def walk(o):
        if isinstance(o, dict):
            for k,v in o.items():
                for cat, arr in scan_text_values_all(str(k)).items():
                    for x in arr: bump(cat, x)
                if isinstance(v, (str,int,float)):
                    for cat, arr in scan_text_values_all(str(v)).items():
                        for x in arr: bump(cat, x)
                else:
                    walk(v)
        elif isinstance(o, list):
            for v in o: walk(v)
        else:
            if isinstance(o, (str,int,float)):
                for cat, arr in scan_text_values_all(str(o)).items():
                    for x in arr: bump(cat, x)
    walk(obj)
    return {k: list(dict.fromkeys(v)) for k,v in vals.items()}

# =========================================================
# 6) Presidio 실행
# =========================================================
def _rows_to_lines(csv_text: str) -> List[str]:
    f = io.StringIO(csv_text)
    reader = csv.DictReader(f)
    lines = []
    for row in reader:
        s = " | ".join(f"{k}: {v}" for k,v in row.items() if v)
        if s: lines.append(s)
    return lines

def _flatten_json_for_presidio(obj: Any) -> str:
    acc: List[str] = []
    def walk(o, prefix=""):
        if isinstance(o, dict):
            for k,v in o.items():
                name = f"{prefix}.{k}" if prefix else k
                if isinstance(v, (str,int,float)):
                    acc.append(f"{name}: {v}")
                else:
                    walk(v, name)
        elif isinstance(o, list):
            for i,v in enumerate(o):
                name = f"{prefix}[{i}]"
                if isinstance(v, (str,int,float)):
                    acc.append(f"{name}: {v}")
                else:
                    walk(v, name)
    walk(obj)
    return " | ".join(acc)

def run_presidio(texts: List[str]) -> List[Dict[str,Any]]:
    if not ENGINE_PII_AVAILABLE:
        return []
    hits: List[Dict[str,Any]] = []
    for t in texts:
        try:
            d = _presidio_analyze_text(t)
            for h in d.get("merged", []):
                hits.append({
                    "entity": h.get("entity"),
                    "text": h.get("text"),
                    "start": h.get("start"),
                    "end": h.get("end"),
                })
        except Exception as e:
            print(f"[warn] Presidio 실행 중 오류: {e}")
    return hits

# =========================================================
# 7) 분류 로직
# =========================================================
def build_target_path(category: str, key: str) -> str:
    fname = os.path.basename(key)
    base = {"public":"public","sensitive":"sensitive","identifiers":"identifiers"}.get(category,"public")
    return f"{CLASSIFY_ROOT}/{base}/{fname}"

def decide_category(meta: Dict[str,Any],
                    findings: Dict[str,Any],
                    presidio_hits: List[Dict[str,Any]]) -> Tuple[str,str]:
    meta_vals = (meta or {}).get("values", {})
    body_vals = findings.get("values_text") or findings.get("values") or findings.get("json_values") or {}
    ents = set(meta_vals.keys()) | set(body_vals.keys()) | {h.get("entity") for h in presidio_hits}

    hints = (meta.get("risk_hints") or {}).get("matched", [])
    low_hints = [h.lower() for h in hints]

    if TREAT_CREDIT_CARD_AS_SENSITIVE and "CREDIT_CARD" in (ents | set(body_vals.keys()) | set(meta_vals.keys())):
        return "sensitive", "신용카드 포함(정책에 따라 민감으로 격상)"

    if ents & ID_ENTS or any(h in low_hints for h in HINTS_IDENTIFIERS):
        return "identifiers", "고유식별정보 포함"

    # Presidio(커스텀)로 잡힌 PIPA 엔티티도 민감으로 분류
    if ents & PIPA_ENTS or any(h in low_hints for h in HINTS_SENSITIVE):
        return "sensitive", "민감정보 포함"

    if ents & GENERAL_PII or any(h in low_hints for h in HINTS_PII):
        return "public", "일반 개인정보 포함"

    return "public", "민감 신호 없음"

# =========================================================
# 8) 콘솔과 유사한 출력 문자열
# =========================================================
def build_console_like(key: str, ctype: str, meta: Dict[str,Any], findings: Dict[str,Any],
                       presidio_hits: List[Dict[str,Any]], category: str, reason: str) -> str:
    lines = []
    lines.append(f"파일: {key}")
    lines.append(f" ├─ 형식: {ctype}")

    mvals = meta.get("values", {})
    if mvals:
        lines.append(" ├─ 메타데이터 탐지:")
        for k, arr in mvals.items():
            lines.append(f" │   • {k}: {arr}")
    else:
        lines.append(" ├─ 메타데이터 탐지: 없음")

    risk = meta.get("risk_hints", {})
    if risk.get("count",0) > 0:
        lines.append(f" │   (위험 힌트 {risk['count']}건: {risk['matched']})")

    body_vals = findings.get("values_text") or findings.get("values") or findings.get("json_values") or {}
    if body_vals:
        lines.append(" ├─ 본문 탐지:")
        for k, arr in body_vals.items():
            lines.append(f" │   • {k}: {arr}")
    else:
        lines.append(" ├─ 본문 탐지: 없음")

    if presidio_hits:
        lines.append(" ├─ Presidio(커스텀 인식기) 결과:")
        for d in presidio_hits:
            lines.append(f" │   • [{d.get('entity')}] '{d.get('text')}'")
    else:
        lines.append(" ├─ Presidio(커스텀 인식기) 결과: 없음")

    target = build_target_path(category, key)
    lines.append(f" ├─ 분류: {category} ({reason})")
    lines.append(f" │   → 저장 경로: {target}")
    lines.append(" └────────────────────────────")
    return "\n".join(lines)

# =========================================================
# 9) 단일 Blob 분석
# =========================================================
def analyze_one_blob(blob: Dict[str,Any]) -> Dict[str,Any]:
    key = blob.get("key","")
    content = blob.get("content", {}) or {}
    meta = scan_metadata(blob)

    text = content.get("text")
    metrics = content.get("metrics")
    findings: Dict[str,Any] = {}
    ctype = "unknown"

    presidio_hits: List[Dict[str,Any]] = []
    if text is not None:
        header_line = text.split("\n",1)[0]
        is_csv = (header_line.count(",") >= 1)
        ctype = "text/csv" if is_csv else "text/plain"
        if is_csv:
            csv_res = detect_in_csv_text(text)
            findings.update(csv_res)
            presidio_hits = run_presidio(_rows_to_lines(text))
        else:
            plain = detect_in_plain_text(text)
            findings.update(plain)
            presidio_hits = run_presidio([text])
    elif metrics is not None:
        ctype = "application/json"
        findings["json_values"] = detect_in_json(metrics)
        flat = _flatten_json_for_presidio(metrics)
        presidio_hits = run_presidio([flat]) if flat else []
    else:
        ctype = "unknown"

    category, reason = decide_category(meta, findings, presidio_hits)
    console_like = build_console_like(
        key=key, ctype=ctype, meta=meta, findings=findings, presidio_hits=presidio_hits,
        category=category, reason=reason
    )

    report = {
        "file": key,
        "type": ctype,
        "metadata": {
            "detected": meta.get("values", {}),
            "risk_hints": meta.get("risk_hints", {})
        },
        "body": {
            "detected": findings.get("values_text") or findings.get("values") or findings.get("json_values") or {}
        },
        "presidio": presidio_hits,
        "classification": {
            "category": category,
            "reason": reason,
            "target_path": build_target_path(category, key)
        },
        "console_like": console_like
    }
    return report

# =========================================================
# 10) 저장/출력
# =========================================================
def organize_and_save(reports: List[Dict[str,Any]], out_json_path: Path):
    for r in reports:
        print("\n" + r["console_like"])

    out_json_path.write_text(json.dumps(reports, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n결과 JSON 저장: {out_json_path.resolve()}")

    base_dir = out_json_path.parent
    for r in reports:
        target_path = base_dir / r["classification"]["target_path"]
        target_path.parent.mkdir(parents=True, exist_ok=True)
        content_text = f"# Original key: {r['file']}\n# Type: {r['type']}\n\n"
        target_path.write_text(content_text, encoding="utf-8")

# =========================================================
# 11) CLI
# =========================================================
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="PII/Sensitive scanner (console-like JSON)")
    parser.add_argument("--input","-i", required=False, default="sample_payload.json", help="입력 payload JSON(리스트)")
    parser.add_argument("--output","-o", required=False, default="results.json", help="저장 파일명(results.json)")
    args = parser.parse_args()

    payload_path = Path(args.input)
    if not payload_path.exists():
        raise SystemExit(f"[!] 입력 파일이 없습니다: {payload_path}")

    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise SystemExit("[!] 입력 JSON은 리스트여야 합니다.")

    reports = [analyze_one_blob(b) for b in payload]
    organize_and_save(reports, Path(args.output))
