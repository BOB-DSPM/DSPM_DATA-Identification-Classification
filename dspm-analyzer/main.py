# -*- coding: utf-8 -*-
import os, re, io, csv, json
from pathlib import Path
from typing import Dict, List, Any, Tuple

# =========================================================
# Presidio 준비
# =========================================================
ENGINE_PII_AVAILABLE = False
try:
    from engine_pii import analyze_text as _presidio_analyze_text
    from engine_pii import list_loaded_recognizers as _presidio_list_loaded
    ENGINE_PII_AVAILABLE = True
    print("[info] Presidio: ON (engine_pii.analyze_text 사용)")
except Exception as e:
    print(f"[warn] Presidio import 실패: {e}  -> Presidio 결과는 비게 나올 수 있습니다.")

# 정책/출력 설정
TREAT_CREDIT_CARD_AS_SENSITIVE = bool(int(os.getenv("TREAT_CREDIT_CARD_AS_SENSITIVE", "0")))
CLASSIFY_ROOT = "classified"
DEBUG_UNMASK = bool(int(os.getenv("DEBUG_UNMASK", "0")))  # 콘솔 마스킹 해제

# =========================================================
# 1) 패턴/힌트
# =========================================================
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
CC_CANDIDATE_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
RRN_RE = re.compile(r"(?<!\d)(\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])[-]?[1-4]\d{6}(?!\d)")

# 전화번호: +82 또는 0 접두 필수
PHONE_RE = re.compile(
    r"(?<!\d)"
    r"(?:\+82[-.\s]?0?|0)"
    r"(?:10|11|16|17|18|19|2|3[1-3]|4[1-4]|5[1-5]|6[1-4])"
    r"[-.\s]?\d{3,4}[-.\s]?\d{4}"
    r"(?!\d)"
)

# ICD-10 (평문 비활성, CSV는 헤더 필요)
ICD10_RE = re.compile(r"\b([A-TV-Z][0-9]{2}(?:\.[0-9A-TV-Z]{1,4})?)\b", re.I)

# 카드 결제 요소
EXPIRY_RE = re.compile(r"\b(0?[1-9]|1[0-2])[/\-](?:\d{2}|\d{4})\b")
CVV_RE    = re.compile(r"\b\d{3,4}\b")
CVV_LABEL_RE = re.compile(
    r"(?:CVV|CVC|카드\s*보안코드)(?:\s*\([^)]+\))?\s*[:\-]?\s*([0-9]{3,4})\b",
    re.I
)
CARD_CONTEXT = (
    "card","visa","master","mastercard","amex","american express",
    "discover","diners","jcb","카드","신용카드","체크카드","카드번호","결제카드","결제","승인","결제번호"
)

# 주소/계좌/DOB
KOREAN_ADDRESS_RE = re.compile(r"""
\b(
 (?:서울|부산|대구|인천|광주|대전|울산|세종|제주|경기|강원|충북|충남|전북|전남|경북|경남)
 (?:특별시|광역시|특별자치시|도)?
 \s*(?:[가-힣]{1,12}(?:시|군|구))?
 \s*(?:[가-힣0-9]{1,20}(?:읍|면|동|리))?
 \s*(?:[A-Za-z가-힣0-9]{1,30}(?:로|길))
 \s*(?:\d{1,4}(?:-\d{1,4})?)?
 (?:\s*(?:번지|지|동|호|층)\s*\d{1,4})?
)
\b
""", re.VERBOSE)
BANK_ACCOUNT_RE = re.compile(r"(?<!\d)(?:\d+-)+\d+(?!\d)")
ACCT_CONTEXT = ("계좌","계좌번호","입금","은행","account","acct","iban")

DOB_RES = [
    re.compile(r"\b(19[0-9]{2}|20[0-9]{2})[-/\.](0[1-9]|1[0-2])[-/\.](0[0-9]|[12][0-9]|3[01])\b"),
    re.compile(r"\b(0[1-9]|[12][0-9]|3[01])[-/\.](0[1-9]|1[0-2])[-/\.](19[0-9]{2}|20[0-9]{2})\b"),
    re.compile(r"\b(19[0-9]{2}|20[0-9]{2})년\s*(0?[1-9]|1[0-2])월\s*(0?[0-9]|[12][0-9]|3[01])일\b"),
    re.compile(r"\b([0-9]{2})([01][0-9])([0-3][0-9])\b"),
]

# ===== 헤더 힌트 =====
ICD10_HEADER_HINTS = [
    "icd10","icd_10","diagnosis_code","diagnosis_code_icd10",
    "icd","dx","diag","진단","진단코드","상병","상병코드"
]
CARD_NUMBER_HEADER_HINTS = ["card","card_number","pan","acct","account_number"]
CARD_EXPIRY_HEADER_HINTS  = ["exp","expiry","expiration","exp_date","valid_thru","valid_until"]
CARD_CVV_HEADER_HINTS     = ["cvv","cvc","cid","csc","security_code"]
CARD_ISSUER_HEADER_HINTS  = ["card_issuer","issuer","brand","scheme"]
ADDRESS_HEADER_HINTS      = ["address","주소","배송지","거주지","도로명","지번"]
BANK_ACCOUNT_HEADER_HINTS = ["bank","bank_account","account_no","acct","계좌","계좌번호","입금"]
DOB_HEADER_HINTS          = ["dob","date_of_birth","dateofbirth","birth","생년월일","출생","출생일"]
ID_HEADER_HINTS_RRN       = ["rrn","resident_registration","주민등록","주민번호","주민등록번호"]
ID_HEADER_HINTS_FRN       = ["frn","foreigner_registration","외국인등록","외국인등록번호","외국인"]
ID_HEADER_HINTS_PPT       = ["passport","passport_no","passport_number","여권","여권번호"]
ID_HEADER_HINTS_DL        = ["driver","driver_license","license_no","dl_number","운전면허","면허번호"]

# 이름 컬럼 힌트 (추가)
NAME_HEADER_HINTS = [
    "name","full_name","first_name","last_name",
    "성명","이름","담당자","작성자","등록자","신청자","수신자","보낸이","받는이",
    "대표","담당","기안자","승인자","검토자"
]

# 라우팅 판단용 엔티티
ID_ENTS = {"KR_RRN","KR_FRN","KR_PASSPORT","KR_DRIVER_LICENSE"}
PIPA_ENTS = {"KOREAN_PIPA_POLITICAL","KOREAN_PIPA_UNION","KOREAN_PIPA_HEALTH","KOREAN_PIPA_SEX_LIFE","KOREAN_PIPA_BELIEF"}
GENERAL_PII = {"EMAIL_ADDRESS","PHONE_NUMBER","IP_ADDRESS","CREDIT_CARD","KOREAN_ADDRESS","KR_BANK_ACCOUNT","DATE_OF_BIRTH","ICD10_CODE","CARD_CVV","CARD_EXPIRY","CARD_ISSUER", "KR_NAME","KR_NAME_ROMA"}

# 파일명 위험 힌트
HINTS_SENSITIVE   = ["political","union","religion","belief","sex","health","medical","diagnosis","patient","pregnancy"]
HINTS_IDENTIFIERS = ["passport","rrn","resident_registration","driver","license","idcard","national_id","ssn"]
HINTS_PII         = ["pii","private","confidential","secret","customer","user","account"]

# =========================================================
# 2) 유틸/마스킹
# =========================================================
def ensure_list(d: Dict[str, List[str]], key: str):
    if key not in d: d[key] = []

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

def _mask_pan(s: str) -> str:
    d = re.sub(r"\D","", s or "")
    if len(d) < 10: return s
    return f"{'*'*(len(d)-4)}{d[-4:]}"

def _mask_values_for_console(values: Dict[str, List[str]]) -> Dict[str, List[str]]:
    if DEBUG_UNMASK:
        return values
    masked = {}
    for k, arr in values.items():
        if k == "CREDIT_CARD":
            masked[k] = [_mask_pan(x) for x in arr]
        elif k == "CARD_CVV":
            masked[k] = ["***" for _ in arr]
        else:
            masked[k] = arr
    return masked

def _norm_hyphen(s: str) -> str:
    return (s or "").translate({ord(c):'-' for c in "\u2010\u2011\u2012\u2013\u2014\u2015"})

def _spans(pattern: re.Pattern, s: str):
    return [(m.start(), m.end()) for m in pattern.finditer(s)]

def _overlap(a, b) -> bool:
    return not (a[1] <= b[0] or b[1] <= a[0])

# 전화번호 간이 타당성
def _is_plausible_kr_phone(raw: str) -> bool:
    d = re.sub(r"\D", "", raw or "")
    if d.startswith("82"):
        d = "0" + d[2:]
    # 길이 10~11, 0 시작
    if not (len(d) in (10,11) and d.startswith("0")):
        return False
    # 010 이동통신 또는 02/0[3-6][1-4] 지역 번호
    if d.startswith("010"):
        return True
    if d.startswith("02"):
        return True
    if re.match(r"^0[3-6][1-4]", d):
        return True
    return False

def _digits_len(s: str) -> int:
    return len(re.sub(r"\D", "", s or ""))

# ===== KR_NAME 후보 추출기 (CSV 이름 컬럼 전용) =====
NAME_CANDIDATE_RE = re.compile(r"(?:[가-힣]{1}(?:\s|·|-)?[가-힣]{1,2})")
def _extract_kr_names(value: str) -> List[str]:
    bad_tail = ("도","시","군","구")  # 전라남도/서울특별시 등 배제
    out: List[str] = []
    v = value or ""
    for m in NAME_CANDIDATE_RE.finditer(v):
        cand = m.group(0)
        core = re.sub(r"[·\-\s]", "", cand)
        if len(core) < 2:
            continue
        if core.endswith(bad_tail):
            continue
        # 주소 문맥 단서가 강하면 제외
        if re.search(r"(도로|대로|로|길|번지|호|층|동)", v):
            continue
        out.append(cand)
    return out

# =========================================================
# 3) CSV 판별(강화 휴리스틱)
# =========================================================
def looks_like_csv(text: str) -> bool:
    lines = [ln for ln in text.replace("\r\n","\n").replace("\r","\n").split("\n") if ln.strip()]
    if len(lines) < 2:
        return False
    sample = "\n".join(lines[:5])
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=[',',';','\t','|'])
    except Exception:
        return False
    try:
        header_fields = next(csv.reader([lines[0]], dialect=dialect))
    except Exception:
        return False
    if len(header_fields) < 2:
        return False
    if sum(1 for h in header_fields if ":" in h) >= len(header_fields) // 2:
        return False
    target_cols = len(header_fields)
    check_lines = lines[1:5]
    ok = 0
    for ln in check_lines:
        try:
            cols = next(csv.reader([ln], dialect=dialect))
            if len(cols) == target_cols:
                ok += 1
        except Exception:
            pass
    return ok >= max(1, len(check_lines) // 2)

# =========================================================
# 4) 평문 스캔(이메일/전화/카드/주소/계좌/DOB) — ICD-10은 평문 비활성
# =========================================================
def scan_text_values_all(s: str) -> Dict[str, List[str]]:
    vals: Dict[str, List[str]] = {}
    if not s: return vals
    s = _norm_hyphen(s)

    # 이메일
    for m in EMAIL_RE.finditer(s):
        ensure_list(vals,"EMAIL_ADDRESS"); vals["EMAIL_ADDRESS"].append(m.group(0))

    # 카드 PAN (평문은 결제/카드 문맥 근접 필수)
    for m in CC_CANDIDATE_RE.finditer(s):
        raw = m.group(0)
        if not luhn_valid(raw):
            continue
        ctx = s[max(0, m.start()-32): min(len(s), m.end()+32)].lower()
        if not any(k in ctx for k in CARD_CONTEXT):
            continue
        ensure_list(vals, "CREDIT_CARD"); vals["CREDIT_CARD"].append(raw)

    # 전화번호(+82/0 접두 필수)
    for m in PHONE_RE.finditer(s):
        cand = m.group(0)
        if not _is_plausible_kr_phone(cand):
            continue
        ensure_list(vals,"PHONE_NUMBER"); vals["PHONE_NUMBER"].append(cand)

    # DOB (컨텍스트 근접)
    DOB_CONTEXT = ("dob","date of birth","date_of_birth","birth","생년월일","출생","출생일")
    for rx in DOB_RES:
        for m in rx.finditer(s):
            left = max(0, m.start()-20); right = min(len(s), m.end()+20)
            if any(k in s[left:right].lower() for k in DOB_CONTEXT):
                ensure_list(vals,"DATE_OF_BIRTH"); vals["DATE_OF_BIRTH"].append(m.group(0))

    # CVV (라벨형)
    for m in CVV_LABEL_RE.finditer(s):
        ensure_list(vals,"CARD_CVV"); vals["CARD_CVV"].append(m.group(1))

    # 주소
    for m in KOREAN_ADDRESS_RE.finditer(s):
        ensure_list(vals,"KOREAN_ADDRESS"); vals["KOREAN_ADDRESS"].append(m.group(0))

    # 계좌 (문맥 근접 필요)
    for m in BANK_ACCOUNT_RE.finditer(s):
        # 숫자 자리수 10~14 보장
        if not (10 <= _digits_len(m.group(0)) <= 14):
            continue
        left = max(0, m.start()-20); right = min(len(s), m.end()+20)
        if any(k in s[left:right].lower() for k in ACCT_CONTEXT):
            ensure_list(vals,"KR_BANK_ACCOUNT"); vals["KR_BANK_ACCOUNT"].append(m.group(0))

    # ICD-10 (평문 활성: 의료 문맥 있을 때만)
    ICD10_RE = re.compile(r"\b([A-TV-Z][0-9]{2}(?:\.[0-9A-TV-Z]{1,4})?)\b", re.I)

    # 평문에서 ICD-10 인정할 '의료 문맥' 단어들 (한/영 혼합)
    ICD10_PLAIN_CONTEXT = (
        "icd10","icd-10","icd","dx","diagnosis","diag","condition","patient","record","chart",
        "상병","상병코드","진단","진단코드","질병","의무기록","진료","의학","의료","차트"
    )
    return vals  # 중복 그대로 표시

# =========================================================
# 5) 헤더 기반 스캔 (CSV 셀 단위)
# =========================================================
def scan_value_with_header(header: str, value: str) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    if value is None:
        return out

    h = (header or "").lower().strip()
    v = _norm_hyphen(str(value).strip())

    # 1) 값 자체 기본 스캔(이메일/전화/카드PAN/주소/계좌/DOB/CVV)
    base = scan_text_values_all(v)
    for k, arr in base.items():
        ensure_list(out, k); out[k].extend(arr)

    # 2) ICD-10: **헤더 힌트 있을 때만** 인정 + 이메일 겹침/근접 '@' 배제
    if any(hint in h for hint in ICD10_HEADER_HINTS):
        email_spans = _spans(EMAIL_RE, v)
        for mm in ICD10_RE.finditer(v.upper()):
            code = mm.group(1).upper()
            span = (mm.start(1), mm.end(1))
            if any(_overlap(span, e) for e in email_spans):
                continue
            if "@" in v[max(0, mm.start()-2): min(len(v), mm.end()+2)]:
                continue
            ensure_list(out, "ICD10_CODE"); out["ICD10_CODE"].append(code)
    else:
        out.pop("ICD10_CODE", None)

    # 3) 카드/계좌는 **헤더 열에서만** 인정(상호 충돌 시 계좌 우선)
    is_card_num_col = any(hint in h for hint in CARD_NUMBER_HEADER_HINTS)
    is_cvv_col      = any(hint in h for hint in CARD_CVV_HEADER_HINTS)
    is_exp_col      = any(hint in h for hint in CARD_EXPIRY_HEADER_HINTS)
    is_bank_col     = any(hint in h for hint in BANK_ACCOUNT_HEADER_HINTS)

    # 카드 PAN
    if is_card_num_col:
        if CC_CANDIDATE_RE.search(v) and luhn_valid(v):
            ensure_list(out, "CREDIT_CARD"); out["CREDIT_CARD"].append(v)
    else:
        out.pop("CREDIT_CARD", None)

    # 카드 유효기간/보안코드
    if is_exp_col:
        m = EXPIRY_RE.search(v)
        if m:
            ensure_list(out, "CARD_EXPIRY"); out["CARD_EXPIRY"].append(m.group(0))
    else:
        out.pop("CARD_EXPIRY", None)

    if is_cvv_col:
        if CVV_RE.fullmatch(v):
            ensure_list(out, "CARD_CVV"); out["CARD_CVV"].append(v)
    else:
        out.pop("CARD_CVV", None)

    # 계좌
    if is_bank_col:
        m = BANK_ACCOUNT_RE.search(v)
        if m and (10 <= _digits_len(m.group(0)) <= 14):
            ensure_list(out, "KR_BANK_ACCOUNT"); out["KR_BANK_ACCOUNT"].append(m.group(0))
    else:
        out.pop("KR_BANK_ACCOUNT", None)

    # 충돌 해소: 같은 셀에서 계좌/카드 동시에 걸리면 계좌 우선
    if is_bank_col and "KR_BANK_ACCOUNT" in out and "CREDIT_CARD" in out:
        out.pop("CREDIT_CARD", None)

    # 4) 고유식별정보(헤더 기반)
    if any(hint in h for hint in ID_HEADER_HINTS_RRN):
        for m in re.finditer(r"(?<!\d)(\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])[-]?[1-4]\d{6}(?!\d)", v):
            ensure_list(out, "KR_RRN"); out["KR_RRN"].append(m.group(0))
    if any(hint in h for hint in ID_HEADER_HINTS_FRN):
        for m in re.finditer(r"(?<!\d)(\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])[-]?[5-8]\d{6}(?!\d)", v):
            ensure_list(out, "KR_FRN"); out["KR_FRN"].append(m.group(0))
    if any(hint in h for hint in ID_HEADER_HINTS_PPT):
        for m in re.finditer(r"(?<![A-Z0-9])[A-Z]\d{8}(?![A-Z0-9])", v):
            ensure_list(out, "KR_PASSPORT"); out["KR_PASSPORT"].append(m.group(0))
    if any(hint in h for hint in ID_HEADER_HINTS_DL):
        for m in re.finditer(r"(?<!\d)\d{2}-\d{2}-\d{6}-\d{2}(?!\d)", v):
            ensure_list(out, "KR_DRIVER_LICENSE"); out["KR_DRIVER_LICENSE"].append(m.group(0))

    # 5) 주소/DOB: 헤더 힌트 있으면 적극 반영(없으면 base 결과 그대로)
    if any(hint in h for hint in ADDRESS_HEADER_HINTS):
        m = KOREAN_ADDRESS_RE.search(v)
        if m:
            ensure_list(out, "KOREAN_ADDRESS"); out["KOREAN_ADDRESS"].append(m.group(0))
    if any(hint in h for hint in DOB_HEADER_HINTS):
        for rx in DOB_RES:
            m = rx.search(v)
            if m:
                ensure_list(out, "DATE_OF_BIRTH"); out["DATE_OF_BIRTH"].append(m.group(0))
                break

    # 6) 이름 컬럼일 때만 KR_NAME 인식 (CSV 전용 헤더 기반)
    if any(hint in h for hint in NAME_HEADER_HINTS):
        names = _extract_kr_names(v)
        if names:
            ensure_list(out, "KR_NAME"); out["KR_NAME"].extend(names)
    else:
        out.pop("KR_NAME", None)

    return out  # 중복 그대로 표시

# =========================================================
# 6) 메타데이터 스캔(파일명 등)
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
        "values": vals,  # 그대로
        "risk_hints": {"count": len(matched), "matched": matched}
    }

# =========================================================
# 7) CSV/Plain 스캐너
# =========================================================
def detect_in_csv_text(text: str) -> Dict[str, Any]:
    normalized = text.replace("\r\n","\n").replace("\r","\n")
    try:
        dialect = csv.Sniffer().sniff(normalized[:2048], delimiters=[',',';','\t','|'])
    except Exception:
        dialect = csv.excel

    values: Dict[str, List[str]] = {}
    rows_scanned = 0
    reader = csv.DictReader(io.StringIO(normalized), dialect=dialect)
    for row in reader:
        rows_scanned += 1
        for col, raw in (row or {}).items():
            if raw is None:
                continue
            found = scan_value_with_header(str(col), str(raw))
            for k, arr in found.items():
                ensure_list(values, k); values[k].extend(arr)

    return {"rows_scanned": rows_scanned, "values_text": values}

def detect_in_plain_text(text: str) -> Dict[str, Any]:
    return {"values": scan_text_values_all(text)}

# =========================================================
# 8) Presidio 실행 + 병합
# =========================================================
def run_presidio(texts: List[str]) -> List[Dict[str,Any]]:
    if not ENGINE_PII_AVAILABLE: return []
    hits: List[Dict[str,Any]] = []
    for t in texts:
        try:
            d = _presidio_analyze_text(t)
            hits.extend(d.get("merged", []))
        except Exception as e:
            print(f"[warn] Presidio 오류: {e}")
    return hits

def _merge_presidio_hits_into_findings(findings: Dict[str,Any], hits: List[Dict[str,Any]], *, is_csv: bool = False):
    """
    Presidio 결과를 본문 탐지 findigs(dict)에 병합.
    CSV일 때는 KR_NAME/KR_NAME_ROMA는 헤더 기반으로만 허용 → 병합 스킵.
    """
    if not hits: return
    tgt = findings.get("values_text") or findings.get("values") or findings.get("json_values")
    if not isinstance(tgt, dict): return
    icd10_rx = re.compile(r"^[A-TV-Z][0-9]{2}(?:\.[0-9A-TV-Z]{1,4})?$", re.I)

    for h in hits:
        ent = (h.get("entity") or "").upper()
        txt = h.get("text") or ""
        if not txt: 
            continue

        # CSV 모드에서는 이름 병합 생략(헤더 기반으로만 인정)
        if is_csv and ent in ("KR_NAME", "KR_NAME_ROMA"):
            continue

        if ent in ("KOREAN_ADDRESS",):
            ensure_list(tgt, "KOREAN_ADDRESS"); tgt["KOREAN_ADDRESS"].append(txt)
        elif ent in ("KR_BANK_ACCOUNT",):
            ensure_list(tgt, "KR_BANK_ACCOUNT"); tgt["KR_BANK_ACCOUNT"].append(txt)
        elif icd10_rx.match(txt):
            ensure_list(tgt, "ICD10_CODE"); tgt["ICD10_CODE"].append(txt.upper())
        elif ent == "KR_NAME":
            ensure_list(tgt, "KR_NAME"); tgt["KR_NAME"].append(txt)
        elif ent == "KR_NAME_ROMA":
            ensure_list(tgt, "KR_NAME_ROMA"); tgt["KR_NAME_ROMA"].append(txt)

# =========================================================
# 9) 분류 로직
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

    # --- 카드 데이터 우선 처리 ---
    if "CARD_CVV" in ents:
        return "sensitive", "결제 보안코드(CVV) 포함(PCI-DSS 저장 금지)"
    if ("CREDIT_CARD" in ents) and (("CARD_CVV" in ents) or ("CARD_EXPIRY" in ents)):
        return "sensitive", "카드번호와 결제정보 조합 포함"
    if TREAT_CREDIT_CARD_AS_SENSITIVE and "CREDIT_CARD" in ents:
        return "sensitive", "신용카드 포함(정책에 따라 민감으로 격상)"

    # --- 고유식별정보 ---
    if ents & ID_ENTS or any(h in low_hints for h in HINTS_IDENTIFIERS):
        return "identifiers", "고유식별정보 포함"

    # --- 민감정보 ---
    if ents & PIPA_ENTS or any(h in low_hints for h in HINTS_SENSITIVE):
        return "sensitive", "민감정보 포함"

    # --- 일반 PII ---
    if ents & GENERAL_PII or any(h in low_hints for h in HINTS_PII):
        return "public", "일반 개인정보 포함"

    return "public", "민감 신호 없음"

# =========================================================
# 10) 콘솔/리포트 빌드
# =========================================================
def build_console_like(key: str, ctype: str, findings: Dict[str,Any],
                       category: str, reason: str) -> str:
    lines = []
    lines.append(f"파일: {key}")
    lines.append(f" ├─ 형식: {ctype}")

    body_vals = findings.get("values_text") or findings.get("values") or findings.get("json_values") or {}
    if body_vals:
        safe_vals = _mask_values_for_console(body_vals)
        lines.append(" ├─ 본문 탐지:")
        for k, arr in safe_vals.items():
            lines.append(f" │   • {k}: {arr}")
    else:
        lines.append(" ├─ 본문 탐지: 없음")

    target = build_target_path(category, key)
    lines.append(f" ├─ 분류: {category} ({reason})")
    lines.append(f" │   → 저장 경로: {target}")
    lines.append(" └────────────────────────────")
    return "\n".join(lines)

# =========================================================
# 11) Blob 분석
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
    if text:
        if looks_like_csv(text):
            ctype = "text/csv"
            res = detect_in_csv_text(text)
            findings.update(res)
            presidio_hits = run_presidio([text])
            _merge_presidio_hits_into_findings(findings, presidio_hits, is_csv=True)
        else:
            ctype = "text/plain"
            res = detect_in_plain_text(text)
            findings.update(res)
            presidio_hits = run_presidio([text])
            _merge_presidio_hits_into_findings(findings, presidio_hits, is_csv=False)
    elif metrics is not None:
        ctype = "application/json"
        findings["json_values"] = {}  # 필요시 확장
    else:
        ctype = "unknown"

    # 분류
    category, reason = decide_category(meta, findings, presidio_hits)
    console_like = build_console_like(key, ctype, findings, category, reason)

    report = {
        "file": key,
        "type": ctype,
        "metadata": {
            "detected": meta.get("values", {}),
            "risk_hints": meta.get("risk_hints", {})
        },
        "body": {"detected": (findings.get("values_text") or findings.get("values") or {})},
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
# 12) 저장/출력
# =========================================================
def organize_and_save(reports: List[Dict[str,Any]], out_json_path: Path):
    console_blocks: List[str] = []

    for r in reports:
        body_detected = r.get("body", {}).get("detected", {})
        if body_detected:
            block = "\n" + r["console_like"]
            print(block)
            console_blocks.append(block)

    out_json_path.write_text(json.dumps(reports, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n결과 JSON 저장: {out_json_path.resolve()}")

    console_path = out_json_path.with_suffix(".console.txt")
    if console_blocks:
        console_path.write_text("\n".join(console_blocks) + "\n", encoding="utf-8")
    else:
        console_path.write_text("# 본문 탐지 결과가 있는 항목이 없어 콘솔 출력이 없습니다.\n", encoding="utf-8")
    print(f"콘솔 출력 사본 저장: {console_path.resolve()}")

    base_dir = out_json_path.parent
    for r in reports:
        target_path = base_dir / r["classification"]["target_path"]
        target_path.parent.mkdir(parents=True, exist_ok=True)
        content_text = (
            f"# Original key: {r['file']}\n"
            f"# Type: {r['type']}\n\n"
            f"## Console-like\n{r['console_like']}\n"
        )
        target_path.write_text(content_text, encoding="utf-8")

# =========================================================
# 13) CLI
# =========================================================
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="PII/Sensitive scanner (console-like JSON & classification)"
    )
    parser.add_argument(
        "--input", "-i",
        default="sample_payload.json",
        help="입력 payload JSON(리스트)"
    )
    parser.add_argument(
        "--output", "-o",
        default="results.json",
        help="저장 파일명(results.json)"
    )
    args = parser.parse_args()

    payload_path = Path(args.input)
    if not payload_path.exists():
        raise SystemExit(f"[!] 입력 파일이 없습니다: {payload_path}")

    try:
        payload = json.loads(payload_path.read_text(encoding="utf-8"))
    except Exception as e:
        raise SystemExit(f"[!] 입력 JSON 로드 실패: {e}")

    if not isinstance(payload, list):
        raise SystemExit("[!] 입력 JSON은 리스트여야 합니다. (예: [{...}, {...}])")

    # 분석 실행
    reports = [analyze_one_blob(b) for b in payload]

    # 저장/출력
    organize_and_save(reports, Path(args.output))
