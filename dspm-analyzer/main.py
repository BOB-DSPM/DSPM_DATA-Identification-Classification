# -*- coding: utf-8 -*-
import os, re, io, csv, json
from pathlib import Path
from typing import Dict, List, Any, Tuple, Optional
from datetime import datetime, timedelta, timezone

ANALYZER_ROOT = Path(__file__).resolve().parent
POLICY_CSV = os.getenv(
    "POLICY_CSV",
    str(ANALYZER_ROOT / "var" / "policies" / "Personal_Infor_List.csv")
)

MATCH_SCOPE = os.getenv("MATCH_SCOPE", "key").lower()

# =========================================================
# Presidio 준비(선택)
# =========================================================
ENGINE_PII_AVAILABLE = False
SPLIT_BY_ENTITY = True
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

# ICD-10 (헤더 기반 + 평문 의료 문맥에서만)
ICD10_RE = re.compile(r"\b([A-TV-Z][0-9]{2}(?:\.[0-9A-TV-Z]{1,4})?)\b", re.I)

# 카드 결제 요소
EXPIRY_RE = re.compile(r"\b(0?[1-9]|1[0-2])[/\-](?:\d{2}|\d{4})\b")
CVV_RE    = re.compile(r"\b\d{3,4}\b")
CVV_LABEL_RE = re.compile(
    r"(?:CVV|CVC|카드\s*보안코드)(?:\s*\([^)]+\))?\s*[:\-]?\s*([0-9]{3,4})\b",
    re.I
)
# CSV 셀형(값만 있는 경우) CVV 후보
CVV_CSV_CELL_RE = re.compile(r"^\s*\d{3,4}\s*$")

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

# 계좌: 평문 비활성(헤더 열에서만). 하이픈(일반/긴 대시) 통일 매칭.
HYPH = r"[-\u2013\u2014\u2015\u2012\u2011\u2010]"
BANK_ACCOUNT_HYPHEN_RE = re.compile(
    rf"(?<!\d)(?:\d{{1,4}}{HYPH}\d{{1,6}}(?:{HYPH}\d{{1,6}})+)(?!\d)"
)

ACCT_CONTEXT = ("계좌","계좌번호","입금","은행","account","acct","iban")

DOB_RES = [
    re.compile(r"\b(19[0-9]{2}|20[0-9]{2})[-/\.](0[1-9]|1[0-2])[-/\.](0[1-9]|[12][0-9]|3[01])\b"),
    re.compile(r"\b(0[1-9]|[12][0-9]|3[01])[-/\.](0[1-9]|1[0-2])[-/\.](19[0-9]{2}|20[0-9]{2})\b"),
    re.compile(r"\b(19[0-9]{2}|20[0-9]{2})년\s*(0?[1-9]|1[0-2])월\s*(0?[0-9]|[12][0-9]|3[01])일\b"),
    re.compile(r"\b([0-9]{2})([01][0-9])([0-3][0-9])\b"),
]

# ===== 헤더 힌트(동의어 확장) =====
ICD10_HEADER_HINTS = [
    "icd10","icd_10","diagnosis_code","diagnosis_code_icd10",
    "icd","dx","diag","진단","진단코드","상병","상병코드",
    "diagnosis","diagnosiscode","icdcode"
]
CARD_NUMBER_HEADER_HINTS = ["card","card_number","pan","acct","account_number","cardnumber","card no","cardno"]
CARD_EXPIRY_HEADER_HINTS  = ["exp","expiry","expiration","exp_date","valid_thru","valid_until","expires"]
CARD_CVV_HEADER_HINTS     = ["cvv","cvc","cid","csc","security_code","card_cvv","cvv_code"]
CARD_ISSUER_HEADER_HINTS  = ["card_issuer","issuer","brand","scheme"]
ADDRESS_HEADER_HINTS      = ["address","주소","배송지","거주지","도로명","지번","billing_address","address_road"]
BANK_ACCOUNT_HEADER_HINTS = [
    "bank","bank_account","account_no","acct","계좌","계좌번호","입금",
    "accountnumber","bankaccount","acct_no","accountno"
]
DOB_HEADER_HINTS          = ["dob","date_of_birth","dateofbirth","birth","생년월일","출생","출생일"]
NAME_HEADER_HINTS         = [
    "name","full_name","first_name","last_name","name_ko","holder_name","cardholder","patient_name",
    "성명","이름","담당자","작성자","등록자","신청자","수신자","보낸이","받는이","대표","담당","기안자","승인자","검토자"
]
ID_HEADER_HINTS_RRN       = ["rrn","resident_registration","주민등록","주민번호","주민등록번호"]
ID_HEADER_HINTS_FRN       = ["frn","foreigner_registration","외국인등록","외국인등록번호","외국인"]
ID_HEADER_HINTS_PPT       = ["passport","passport_no","passport_number","여권","여권번호"]
ID_HEADER_HINTS_DL        = ["driver","driver_license","license_no","dl_number","운전면허","면허번호"]

# 라우팅 판단용 엔티티
ID_ENTS = {"KR_RRN","KR_FRN","KR_PASSPORT","KR_DRIVER_LICENSE"}
PIPA_ENTS = {"KOREAN_PIPA_POLITICAL","KOREAN_PIPA_UNION","KOREAN_PIPA_HEALTH","KOREAN_PIPA_SEX_LIFE","KOREAN_PIPA_BELIEF"}
GENERAL_PII = {"EMAIL_ADDRESS","PHONE_NUMBER","IP_ADDRESS","CREDIT_CARD","KOREAN_ADDRESS","KR_BANK_ACCOUNT","DATE_OF_BIRTH","CARD_CVV","CARD_EXPIRY","CARD_ISSUER", "KR_NAME","KR_NAME_ROMA"}

# 파일명 위험 힌트
HINTS_SENSITIVE   = ["political","union","religion","belief","sex","health","medical","diagnosis","patient","pregnancy"]
HINTS_IDENTIFIERS = ["passport","rrn","resident_registration","driver","license","idcard","national_id","ssn"]
HINTS_PII         = ["pii","private","confidential","secret","customer","user","account"]

# =========================================================
# 2) 유틸/마스킹
# =========================================================
def _safe_key_filename(orig_key: str) -> str:
    safe = re.sub(r'[<>:"\\|?*]', "", orig_key or "unknown")
    safe = safe.strip().replace("..", ".")
    return safe.strip("/")

def _key_stem_lower(key: str) -> Optional[str]:
    """
    S3 key에서 확장자를 제거한 파일명(stem)을 소문자로 반환.
    예) 'folder/a.csv' -> 'a', 'health_dataset.csv' -> 'health_dataset'
    """
    if not key:
        return None
    base = os.path.basename(str(key))
    if not base:
        return None
    stem = base.rsplit(".", 1)[0]
    stem = (stem or "").strip()
    return stem.lower() if stem else None

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
    # 마스킹 해제 
    return values

def _norm_hyphen(s: str) -> str:
    return (s or "").translate({ord(c):'-' for c in "\u2010\u2011\u2012\u2013\u2014\u2015"})

def _spans(pattern: re.Pattern, s: str):
    return [(m.start(), m.end()) for m in pattern.finditer(s)]

def _overlap(a, b) -> bool:
    return not (a[1] <= b[0] or b[1] <= a[0])

def _is_plausible_kr_phone(raw: str) -> bool:
    d = re.sub(r"\D", "", raw or "")
    if d.startswith("82"):
        d = "0" + d[2:]
    if not (len(d) in (10,11) and d.startswith("0")):
        return False
    if d.startswith("010") or d.startswith("02") or re.match(r"^0[3-6][1-4]", d):
        return True
    return False

def _digits_len(s: str) -> int:
    return len(re.sub(r"\D","", s or ""))

def _try_parse_dt(s: str):
    if not s:
        return None
    s = str(s).strip()
    # ISO 8601 with Z
    if s.endswith("Z"):
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        except Exception:
            pass
    # plain ISO 8601
    try:
        
        dt = datetime.fromisoformat(s)
        # *** 수정: timezone이 없으면 UTC 부여 ***
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        pass
    # common formats
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S",
                "%Y-%m-%d", "%Y/%m/%d", "%Y.%m.%d",
                "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(s, fmt)
            # *** timezone이 없으면 UTC 부여 ***
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            continue
    return None

def _norm_header(h: str) -> str:
    h = (h or "").strip().lower()
    h = re.sub(r"[\s\-]+", "_", h)
    h = re.sub(r"[^\w]", "", h)
    return h

def _hdr_any(header_raw: str, hints: List[str]) -> bool:
    h_raw = (header_raw or "")
    h_norm = _norm_header(h_raw)
    for hint in hints:
        if hint in h_raw.lower(): return True
        if hint in h_norm: return True
        if h_norm == hint: return True
    return False

_TOKEN_SPLIT_RE = re.compile(r"[^\w@.+-]+", re.UNICODE)

def _filename_tokens(key: str) -> List[str]:
    """
    파일 경로에서 파일명(basename)과 마지막 2~3개 디렉터리명을 추려
    토큰 단위로 분해하여 반환.
    - 이메일/도메인/연월일/ID 등이 토큰으로 남도록 @ . + - 는 유지
    - 너무 긴 숫자 나열은 scan_text_values_all의 필터(카드/전화/생년월일 문맥)에서 걸러짐
    """
    if not key:
        return []
    parts = [p for p in key.strip("/").split("/") if p]
    tail = parts[-3:] if len(parts) >= 3 else parts  # 마지막 3개 세그먼트만
    toks: List[str] = []
    for seg in tail:
        for t in _TOKEN_SPLIT_RE.split(seg):
            if t:
                toks.append(t)
    # 중복 제거(순서 유지)
    return list(dict.fromkeys(toks))

def _derive_source_label(key: str) -> Optional[str]:
    k = (key or "").strip()
    if not k or "/" not in k:
        return None
    parts = k.split("/")
    if len(parts) < 2:
        return None
    svc = parts[0]
    ident = None
    if svc == "s3" and len(parts) >= 3:
        maybe_id = parts[2]
        ident = maybe_id.rsplit(".", 1)[0]
    if not ident:
        for p in reversed(parts[1:]):
            if p and not p.startswith("_"):
                ident = p.rsplit(".", 1)[0]
                break
    if svc and ident:
        return f"{svc}/{ident}"
    return None

# ── 경로에서 날짜(YYYY[/MM[/DD]]) 추론 ─────────────────────
_DATE_PATTERNS = [
    re.compile(r"(?P<y>20\d{2}|19\d{2})[/-](?P<m>0[1-9]|1[0-2])[/-](?P<d>0[1-9]|[12]\d|3[01])"),
    re.compile(r"(?P<y>20\d{2}|19\d{2})[/-](?P<m>0[1-9]|1[0-2])"),
    re.compile(r"(?P<y>20\d{2}|19\d{2})"),
]

def _parse_date_from_key(key: str) -> Optional[datetime]:
    s = (key or "").replace("\\", "/")
    for rx in _DATE_PATTERNS:
        m = rx.search(s)
        if m:
            y = int(m.group("y"))
            mth = int(m.group("m")) if "m" in m.groupdict() and m.group("m") else 1
            d = int(m.group("d")) if "d" in m.groupdict() and m.group("d") else 1
            try:
                return datetime(y, mth, d, tzinfo=timezone.utc)
            except Exception:
                pass
    return None

# ── 정책 인덱스 전역 초기화 ──────────────────────────────
try:
    from policies.loader import load_policies
    from matcher.bucket_match import build_policy_slug_index, map_bucket_to_policy
except Exception:
    load_policies = None
    build_policy_slug_index = None
    map_bucket_to_policy = None

_POLICIES: List[Any] = []
slug_index: Dict[str, Any] = {}

def _init_policy_index():
    """POLICY_CSV에서 정책을 읽어 1회 전역 인덱스 구축"""
    global _POLICIES, slug_index
    if slug_index or not load_policies or not build_policy_slug_index:
        return
    p = Path(POLICY_CSV)
    try:
        if p.exists():
            _POLICIES = load_policies(str(p))
            slug_index = build_policy_slug_index(_POLICIES)
        else:
            print(f"[warn] 정책 CSV 미존재: {p}")
    except Exception as e:
        print(f"[warn] 정책 CSV 로드 오류: {e}")
        _POLICIES = []
        slug_index = {}

def _extract_bucket(key: str):
    if not key:
        return None
    s = str(key).replace("\\", "/")
    if s.startswith("s3://"):
        s = s[5:]
    elif s.startswith("s3/"):
        s = s[3:]
    # 첫 세그먼트가 버킷. 슬래시 없으면 매핑하지 않음
    return s.split("/", 1)[0] if "/" in s else None

# =========================================================
# 3) CSV 판별
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
# 4) 평문 스캔 — 계좌 평문 비활성, ICD10은 의료 문맥에서만
# =========================================================
ICD10_PLAIN_CONTEXT = (
    "diagnosis","diagnoses","icd","icd-10","icd10","상병","상병코드",
    "진단","진단코드","환자","의무기록","차트","병력","진료","투약","복약","처방","검사","건강"
)

def _extract_icd10_in_plain(s: str) -> List[str]:
    hits: List[str] = []
    email_spans = _spans(EMAIL_RE, s)
    for mm in ICD10_RE.finditer(s):
        code = mm.group(1).upper()
        span = (mm.start(1), mm.end(1))
        if any(_overlap(span, e) for e in email_spans):
            continue
        ctx = s[max(0, mm.start()-28): min(len(s), mm.end()+28)].lower()
        if any(k in ctx for k in ICD10_PLAIN_CONTEXT):
            hits.append(code)
    return hits

def scan_text_values_all(s: str) -> Dict[str, List[str]]:
    vals: Dict[str, List[str]] = {}
    if not s: return vals
    s = _norm_hyphen(s)

    for m in EMAIL_RE.finditer(s):
        ensure_list(vals,"EMAIL_ADDRESS"); vals["EMAIL_ADDRESS"].append(m.group(0))

    for m in CC_CANDIDATE_RE.finditer(s):
        raw = m.group(0)
        if not luhn_valid(raw):
            continue
        ctx = s[max(0, m.start()-32): min(len(s), m.end()+32)].lower()
        if not any(k in ctx for k in CARD_CONTEXT):
            continue
        ensure_list(vals, "CREDIT_CARD"); vals["CREDIT_CARD"].append(raw)

    for m in PHONE_RE.finditer(s):
        cand = m.group(0)
        if not _is_plausible_kr_phone(cand):
            continue
        ensure_list(vals,"PHONE_NUMBER"); vals["PHONE_NUMBER"].append(cand)

    DOB_CONTEXT = ("dob","date of birth","date_of_birth","birth","생년월일","출생","출생일")
    for rx in DOB_RES:
        for m in rx.finditer(s):
            left = max(0, m.start()-20); right = min(len(s), m.end()+20)
            if any(k in s[left:right].lower() for k in DOB_CONTEXT):
                ensure_list(vals,"DATE_OF_BIRTH"); vals["DATE_OF_BIRTH"].append(m.group(0))

    for m in CVV_LABEL_RE.finditer(s):
        ensure_list(vals,"CARD_CVV"); vals["CARD_CVV"].append(m.group(1))

    for m in KOREAN_ADDRESS_RE.finditer(s):
        ensure_list(vals,"KOREAN_ADDRESS"); vals["KOREAN_ADDRESS"].append(m.group(0))

    icd_hits = _extract_icd10_in_plain(s)
    if icd_hits:
        ensure_list(vals, "ICD10_CODE"); vals["ICD10_CODE"].extend(icd_hits)

    # 계좌 평문 비활성
    return vals

# =========================================================
# 5) 헤더 기반 스캔 (CSV 셀 단위)
# =========================================================
def _looks_like_kr_name(v: str) -> bool:
    v = (v or "").strip()
    if not v: return False
    core = re.sub(r"[·\-\s]", "", v)
    if not re.fullmatch(r"[가-힣]{2,4}", core):
        return False
    if EMAIL_RE.search(v) or re.search(r"(https?://|www\.)", v) or re.search(r"[/\\]\w", v):
        return False
    return True

def scan_value_with_header(header: str, value: str) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    if value is None:
        return out

    h_raw = (header or "")
    h = _norm_header(h_raw)
    v = _norm_hyphen(str(value).strip())

    # 1) 기본 평문 스캔
    base = scan_text_values_all(v)
    for k, arr in base.items():
        ensure_list(out, k); out[k].extend(arr)

    # 2) ICD-10: 헤더 힌트가 있을 때만 적극
    if _hdr_any(h_raw, ICD10_HEADER_HINTS):
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
        # 평문 문맥으로 잡힌 것만 유지
        pass

    # 3) 카드/계좌는 헤더 열에서만 인정
    is_card_num_col = _hdr_any(h_raw, CARD_NUMBER_HEADER_HINTS)
    is_cvv_col      = _hdr_any(h_raw, CARD_CVV_HEADER_HINTS)
    is_exp_col      = _hdr_any(h_raw, CARD_EXPIRY_HEADER_HINTS)
    is_bank_col     = _hdr_any(h_raw, BANK_ACCOUNT_HEADER_HINTS)

    if is_card_num_col:
        if CC_CANDIDATE_RE.search(v) and luhn_valid(v):
            ensure_list(out, "CREDIT_CARD"); out["CREDIT_CARD"].append(v)
    else:
        out.pop("CREDIT_CARD", None)

    if is_exp_col:
        m = EXPIRY_RE.search(v)
        if m:
            ensure_list(out, "CARD_EXPIRY"); out["CARD_EXPIRY"].append(m.group(0))
    else:
        out.pop("CARD_EXPIRY", None)

    if is_cvv_col:
        if CVV_CSV_CELL_RE.fullmatch(v):
            ensure_list(out, "CARD_CVV"); out["CARD_CVV"].append(v.strip())

    if is_bank_col:
        m = BANK_ACCOUNT_HYPHEN_RE.search(v)
        if m and (10 <= _digits_len(m.group(0)) <= 14):
            ensure_list(out, "KR_BANK_ACCOUNT"); out["KR_BANK_ACCOUNT"].append(m.group(0))
    else:
        out.pop("KR_BANK_ACCOUNT", None)

    if is_bank_col and "KR_BANK_ACCOUNT" in out and "CREDIT_CARD" in out:
        out.pop("CREDIT_CARD", None)

    # 4) 고유식별정보(헤더 기반)
    if _hdr_any(h_raw, ID_HEADER_HINTS_RRN):
        for m in re.finditer(r"(?<!\d)(\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])[-]?[1-4]\d{6}(?!\d)", v):
            ensure_list(out, "KR_RRN"); out["KR_RRN"].append(m.group(0))
    if _hdr_any(h_raw, ID_HEADER_HINTS_FRN):
        for m in re.finditer(r"(?<!\d)(\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])[-]?[5-8]\d{6}(?!\d)", v):
            ensure_list(out, "KR_FRN"); out["KR_FRN"].append(m.group(0))
    if _hdr_any(h_raw, ID_HEADER_HINTS_PPT):
        for m in re.finditer(r"(?<![A-Z0-9])[A-Z]\d{8}(?![A-Z0-9])", v):
            ensure_list(out, "KR_PASSPORT"); out["KR_PASSPORT"].append(m.group(0))
    if _hdr_any(h_raw, ID_HEADER_HINTS_DL):
        for m in re.finditer(r"(?<!\d)\d{2}-\d{2}-\d{6}-\d{2}(?!\d)", v):
            ensure_list(out, "KR_DRIVER_LICENSE"); out["KR_DRIVER_LICENSE"].append(m.group(0))

    # 5) 주소/DOB/이름: 헤더 힌트 있으면 적극
    if _hdr_any(h_raw, ADDRESS_HEADER_HINTS):
        m = KOREAN_ADDRESS_RE.search(v)
        if m:
            ensure_list(out, "KOREAN_ADDRESS"); out["KOREAN_ADDRESS"].append(m.group(0))

    if _hdr_any(h_raw, DOB_HEADER_HINTS):
        for rx in DOB_RES:
            m = rx.search(v)
            if m:
                ensure_list(out, "DATE_OF_BIRTH"); out["DATE_OF_BIRTH"].append(m.group(0))
                break

    if _hdr_any(h_raw, NAME_HEADER_HINTS):
        if _looks_like_kr_name(v):
            ensure_list(out, "KR_NAME"); out["KR_NAME"].append(re.sub(r"\s+", "", v))
    else:
        out.pop("KR_NAME", None)

    return out

# =========================================================
# 6) 메타데이터 스캔
# =========================================================
def scan_metadata(blob: Dict[str,Any]) -> Dict[str,Any]:
    key = str(blob.get("key",""))
    vals: Dict[str, List[str]] = {}

    # 기존: key/last_modified/size 문자열에서 평문 패턴 스캔(과도탐지 거의 없음)
    for field in ("key","last_modified","size"):
        found = scan_text_values_all(str(blob.get(field,"")))
        for k, arr in found.items():
            ensure_list(vals,k); vals[k].extend(arr)

    # 기존: metadata/tags/labels 딕셔너리 키/값도 스캔
    for field in ("metadata","tags","labels"):
        md = blob.get(field)
        if isinstance(md, dict):
            for mk, mv in md.items():
                for k, arr in scan_text_values_all(str(mk)).items():
                    ensure_list(vals,k); vals[k].extend(arr)
                for k, arr in scan_text_values_all(str(mv)).items():
                    ensure_list(vals,k); vals[k].extend(arr)

    # NEW: 파일명/경로 토큰을 본문처럼 실제 패턴으로 스캔
    # - basename 뿐 아니라 마지막 2~3 세그먼트까지 커버
    # - EMAIL/PHONE/RRN 등 실제 정규식에 '정답'이 나와야만 잡힘
    fname_tokens = _filename_tokens(key)
    if fname_tokens:
        # 토큰 각각을 개별 텍스트로 간주하여 스캔
        for tok in fname_tokens:
            found = scan_text_values_all(tok)
            for k, arr in found.items():
                ensure_list(vals,k); vals[k].extend(arr)

        # 토큰을 공백 결합해 한 번 더 스캔 (예: john.doe+id-010-1234-5678.txt 같은 케이스)
        joined = " ".join(fname_tokens)
        found_joined = scan_text_values_all(joined)
        for k, arr in found_joined.items():
            ensure_list(vals,k); vals[k].extend(arr)

    return {"values": vals}

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

    # created_at 후보 헤더(소문자/정규화)
    CREATED_AT_HEADER_HINTS = [
        "created_at", "created", "ingested_at", "uploaded_at", "last_modified",
        "생성일", "업로드일", "등록일", "기준일자", "기준일", "작성일"
    ]

    csv_row_created: List[Dict[str, Any]] = []   # 행별 created_at만 보관
    rows_detail: List[Dict[str, Any]] = [] 

    fieldnames = [fn or "" for fn in (reader.fieldnames or [])]
    def _is_created_col(h: str) -> bool:
        h_raw = (h or "")
        h_norm = _norm_header(h_raw)
        return any(hint in h_raw.lower() or hint in h_norm or h_norm == hint for hint in CREATED_AT_HEADER_HINTS)

    created_header_keys = [h for h in fieldnames if _is_created_col(h)]

    # *** 디버깅 출력 추가 ***
    print(f"[DEBUG CSV] 헤더: {fieldnames}")
    print(f"[DEBUG CSV] created_at 매칭된 헤더: {created_header_keys}")

    for row_no, row in enumerate(reader, start=2):
        rows_scanned += 1

        # (A) 이 행의 엔티티만 모으는 딕셔너리 (행 단위)
        row_entities: Dict[str, List[str]] = {}

        # (B) 값/엔티티 스캔 — 전체 합산(values) + 행 단위(row_entities) 모두 채움
        for col, raw in (row or {}).items():
            if raw is None:
                continue
            found = scan_value_with_header(str(col), str(raw))
            # 전체 합산
            for k, arr in found.items():
                ensure_list(values, k); values[k].extend(arr)
            # 행 단위
            for k, arr in found.items():
                ensure_list(row_entities, k); row_entities[k].extend(arr)

        # (C) created_at 추출 (이 행)
        created_iso = None
        if created_header_keys:
            for col in created_header_keys:
                raw = row.get(col)
                if not raw:
                    continue
                dt = _try_parse_dt(raw)
                if dt:
                    created_iso = dt.isoformat()
                    csv_row_created.append({"row": row_no, "created_at": created_iso})
                    break

        # (D) 행 단위 결과에 저장 (원본 행 일부도 함께 담아두면 디버깅/알림문에 사용 가능)
        rows_detail.append({
            "row": row_no,
            "created_at": created_iso,
            "entities": row_entities,
            # 필요시 식별에 쓸 주요 컬럼들을 일부만 보관:
            "row_key_fields": {
                "health_id": row.get("health_id"),
                "name_ko": row.get("name_ko"),
                "email": row.get("email"),
                "phone": row.get("phone"),
            }
        })

    out: Dict[str, Any] = {
        "rows_scanned": rows_scanned,
        "values_text": values,
        "rows_detail": rows_detail,    
    }
    if csv_row_created:
        out["csv_row_created"] = csv_row_created

    return out

def detect_in_plain_text(text: str) -> Dict[str, Any]:
    return {"values": scan_text_values_all(text)}

# =========================================================
# 8) Presidio 실행 + 병합(보수적)
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
    if not hits: return
    tgt = findings.get("values_text") or findings.get("values") or findings.get("json_values")
    if not isinstance(tgt, dict): return
    icd10_rx = re.compile(r"^[A-TV-Z][0-9]{2}(?:\.[0-9A-TV-Z]{1,4})?$", re.I)

    for h in hits:
        ent = (h.get("entity") or "").upper()
        txt = h.get("text") or ""
        if not txt: continue

        if ent in ("KR_NAME", "KR_NAME_ROMA"):
            continue
        if ent == "KOREAN_ADDRESS":
            ensure_list(tgt, "KOREAN_ADDRESS"); tgt["KOREAN_ADDRESS"].append(txt)
        elif ent == "KR_BANK_ACCOUNT":
            # 계좌는 헤더 기반에서만: 기본 미병합
            pass
        elif icd10_rx.match(txt):
            ensure_list(tgt, "ICD10_CODE"); tgt["ICD10_CODE"].append(txt.upper())

# =========================================================
# 9) 분류 로직
# =========================================================
def _bucket_for_entity(ent: str) -> str:
    """
    PIPA 기준 버킷 매핑:
      - 민감정보(sensitive): 건강/신념/정치/노조/성생활 등
      - 고유식별(identifiers): 주민번호/외국인등록/여권/운전면허
      - 그 외 개인정보(public): 이메일/전화/주소/카드/계좌/생년월일/CVV 등
    """
    ent = (ent or "").upper()

    # PIPA 민감정보
    if ent in PIPA_ENTS or ent == "ICD10_CODE":
        return "sensitive"

    # 고유식별
    if ent in ID_ENTS:
        return "identifiers"

    # 나머지 
    return "public"

def build_target_path(category: str, key: str) -> str:
    fname = os.path.basename(key)
    base = {"public":"public","sensitive":"sensitive","identifiers":"identifiers"}.get(category,"public")
    return f"{CLASSIFY_ROOT}/{base}/{fname}"

def decide_category(meta: Dict[str,Any],
                    findings: Dict[str,Any],
                    presidio_hits: List[Dict[str,Any]]) -> Tuple[str,str]:
    """
    최종 카테고리 구분:
      - identifiers : 고유식별정보 포함
      - sensitive   : PIPA 민감(정치/노조/신념/성생활/건강) 또는 ICD10_CODE 포함
      - public      : 일반 개인정보(이메일/전화/주소/계좌/카드/DOB/이름 등) 포함
      - none        : 본문/메타 모두 개인정보 신호 없음
    """

    meta_vals = (meta or {}).get("values", {})
    body_vals = findings.get("values_text") or findings.get("values") or findings.get("json_values") or {}

    ents_meta = {(k or "").upper() for k in meta_vals.keys()}
    ents_body = {(k or "").upper() for k in body_vals.keys()}
    ents_pres = {(h.get("entity") or "").upper() for h in presidio_hits if h.get("entity")}
    ents = ents_meta | ents_body | ents_pres

    # 고유식별 우선
    if ents & ID_ENTS:
        return "identifiers", "고유식별정보 포함"

    # 민감(PIPA) 또는 ICD-10(건강정보)
    if (ents & PIPA_ENTS) or ("ICD10_CODE" in ents):
        return "sensitive", "민감정보 포함"

    # 일반 개인정보(이메일/전화/주소/카드/계좌/생년월일/이름 등)
    if ents & GENERAL_PII:
        return "public", "개인정보 포함"

    # 엔티티가 전혀 없으면 none
    return "none", "개인정보 없음"

# =========================================================
# 10) 콘솔/리포트 빌드
# =========================================================
def build_console_like(key: str, ctype: str, findings: Dict[str,Any],
                       category: str, reason: str) -> str:
    lines = []
    lines.append(f"파일: {key}")

    src = _derive_source_label(key)
    if src:
        lines.append(f" ├─ 소스: {src}")

    lines.append(f" ├─ 형식: {ctype}")

    # 추가된 부분: values 사전도 함께 확인
    values_dict = findings.get("values_text") or findings.get("values") or findings.get("json_values") or {}

    rb   = findings.get("__retention_base__")       or values_dict.get("__retention_base__")
    due  = findings.get("__retention_due_at__")     or values_dict.get("__retention_due_at__")
    viol = findings.get("__retention_violation__")  or values_dict.get("__retention_violation__")

    if rb or due:
        lines.append(" ├─ 보존 기준:")
        if isinstance(rb, dict) and (rb.get("source") or rb.get("value")):
            lines.append(f" │   • 기준 소스: {rb.get('source')}")
            lines.append(f" │   • 기준 값  : {rb.get('value')}")
        if due is not None:
            lines.append(f" │   • 만료 시점: {due}  ({'위반' if viol else '정상'})")

    body_vals = values_dict
    if body_vals:
        safe_vals = _mask_values_for_console(body_vals)
        lines.append(" ├─ 본문 탐지:")
        for k, arr in safe_vals.items():
            lines.append(f" │   • {k}: {arr}")
    else:
        lines.append(" ├─ 본문 탐지: 없음")

    if body_vals:
        safe_key = _safe_key_filename(key)
        lines.append(" ├─ 저장 경로(엔티티별):")
        for ent, vals in body_vals.items():
            if not vals:
                continue
            bucket = _bucket_for_entity(ent)
            per_ent_path = f"{CLASSIFY_ROOT}/{bucket}/{safe_key}__{ent}.txt"
            lines.append(f" │   • {ent}: {per_ent_path}")

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
    rows_detail: List[Dict[str, Any]] = [] 
    if text:
        if looks_like_csv(text):
            ctype = "text/csv"
            res = detect_in_csv_text(text)
            findings.update(res)
            # CSV일 때만 행단위 created_at 반영
            row_list = res.get("csv_row_created")
            if row_list:
                meta.setdefault("csv_meta", {})
                meta["csv_meta"]["row_created"] = row_list
            
            rows_detail = res.get("rows_detail") or []

            presidio_hits = run_presidio([text])
            _merge_presidio_hits_into_findings(findings, presidio_hits, is_csv=True)
        else:
            ctype = "text/plain"
            res = detect_in_plain_text(text)
            findings.update(res)
            # 평문 분기에서는 created_at 행리스트/최솟값 등의 처리를 하지 않음
            presidio_hits = run_presidio([text])
            _merge_presidio_hits_into_findings(findings, presidio_hits, is_csv=False)
    elif metrics is not None:
        ctype = "application/json"
        findings["json_values"] = {}
    else:
        ctype = "unknown"

    category, reason = decide_category(meta, findings, presidio_hits)
    
    # 엔티티별 저장 경로 계산
    body_vals_for_paths = findings.get("values_text") or findings.get("values") or findings.get("json_values") or {}
    safe_key = _safe_key_filename(key)
    saved_paths = {}
    for ent, vals in (body_vals_for_paths or {}).items():
        if not vals:
            continue
        bucket = _bucket_for_entity(ent)
        saved_paths[ent] = f"{CLASSIFY_ROOT}/{bucket}/{safe_key}__{ent}.txt"

    console_like = build_console_like(key, ctype, findings, category, reason)

    report = {
        "file": key,
        "type": ctype,
        "metadata": {
            "detected": meta.get("values", {}),
            "csv_meta": meta.get("csv_meta", {}),
            "risk_hints": meta.get("risk_hints", {})
        },
        "body": {"detected": (findings.get("values_text") or findings.get("values") or {})},
        "body_rows": rows_detail, 
        "presidio": presidio_hits,
        "classification": {
            "category": category,
            "reason": reason,
            "saved_paths": saved_paths
        },
        "console_like": console_like
    }
    return report

def enrich_with_policy(rec: dict) -> dict:
    _init_policy_index()
    global slug_index

    # 기본값 초기화
    rec["policy_map"] = None
    rec["retention_due_at"] = None
    rec["retention_violation"] = None
    rec["retention_base"] = None

    # 정책 인덱스 없으면 매핑 종료
    if not slug_index:
        return rec

    # --- 여기부터: key(stem) 기준 매핑만 허용 ---
    key_stem = _key_stem_lower(rec.get("file") or rec.get("key") or "")
    if not key_stem:
        return rec

    # slug_index는 소문자 키라고 가정하고, 동일하게 소문자 stem으로 매핑
    p = map_bucket_to_policy(key_stem, slug_index)
    if not p:
        return rec  # 매핑 실패 시: 이후 DEFAULT_ROW_RETENTION_DAYS로 행 단위 계산 가능

    rec["policy_map"] = {
        "policy_id": p.policy_id,
        "file_name": p.file_name,
        "retention_raw": p.retention_raw,
        "retention_type": p.retention_type,
        "retention_days": p.retention_days,
    }

    rec["retention_due_at"] = None
    rec["retention_violation"] = None
    rec["retention_base"] = None

    if not (p.retention_type == "fixed" and p.retention_days):
        return rec

    row_list = ((rec.get("metadata") or {}).get("csv_meta") or {}).get("row_created") or []
    debug_also_file_level = bool(int(os.getenv("DEBUG_FILE_RETENTION_ALSO_WHEN_ROW_CREATED", "0")))

    if row_list and not debug_also_file_level:
        rec["retention_base"] = {"source": "csv_row_created", "value": f"rows={len(row_list)}"}
        return rec

    meta = rec.get("metadata") or {}
    base_dt = None
    base_info = None

    base_raw = meta.get("last_modified") or rec.get("last_modified")
    if base_dt is None and base_raw:
        dt = _try_parse_dt(base_raw)
        if dt:
            base_dt = dt
            base_info = {"source": "last_modified", "value": str(base_raw)}

    if base_dt is None:
        dt_from_key = _parse_date_from_key(rec.get("file") or rec.get("key") or "")
        if dt_from_key is not None:
            base_dt = dt_from_key
            base_info = {"source": "key_path_date", "value": dt_from_key.isoformat()}

    if base_dt is None:
        base_raw = meta.get("creation_date") or rec.get("creation_date")
        if base_raw:
            dt = _try_parse_dt(base_raw)
            if dt:
                base_dt = dt
                base_info = {"source": "creation_date", "value": str(base_raw)}

    if base_dt is not None:
        try:
            days = int(p.retention_days)
        except Exception:
            days = int(str(p.retention_days).strip() or "0")

        due = base_dt + timedelta(days=days)
        rec["retention_due_at"] = due.isoformat()
        rec["retention_violation"] = (datetime.now(timezone.utc) > due)
        rec["retention_base"] = base_info
    else:
        if not row_list:
            rec["retention_base"] = {"source": "none", "value": ""}

    return rec

def organize_and_save(reports: List[Dict[str,Any]], out_json_path: Path):
    # ─────────────────────────────────────────────────────────
    # 정책 CSV가 없을 때 기본 행(ROW) 보존기간 일수 (없으면 0=미계산)
    DEFAULT_ROW_RETENTION_DAYS = int(os.getenv("DEFAULT_ROW_RETENTION_DAYS", "0"))
    # 모든 파일에서 초과(만료)된 행만 모아 alerts.json으로 저장
    alerts_bucket: List[Dict[str, Any]] = []
    # ─────────────────────────────────────────────────────────

    print(f"\n[DEBUG] DEFAULT_ROW_RETENTION_DAYS = {DEFAULT_ROW_RETENTION_DAYS}")

    enriched_reports = []
    for r in reports:
        # 1) 정책 enrich (retention_days 등 계산에 필요)
        r = enrich_with_policy(r)

        # 2) ── 행(ROW) 단위 보존기간 계산 ─────────────────────────
        # policy_days: 정책 CSV(fixed) > 기본값 환경변수(DEFAULT_ROW_RETENTION_DAYS)
        policy_days = None
        pm = r.get("policy_map") or {}
        if pm.get("retention_type") == "fixed" and pm.get("retention_days"):
            try:
                policy_days = int(pm["retention_days"])
            except Exception:
                policy_days = None
        if policy_days is None and DEFAULT_ROW_RETENTION_DAYS > 0:
            policy_days = DEFAULT_ROW_RETENTION_DAYS

        print(f"\n[DEBUG] 파일: {r.get('file')}")
        print(f"[DEBUG] policy_days: {policy_days}")

        # rows_detail 키(또는 body_rows 키)로 행별 정보 가져오기 (둘 다 지원)
        rows_detail = r.get("body_rows") or r.get("rows_detail") or []
        print(f"[DEBUG] rows_detail 개수: {len(rows_detail)}")
        
        row_alerts: List[Dict[str, Any]] = []
        now_utc = datetime.now(timezone.utc)

        if policy_days:
            for rd in rows_detail:
                created_iso = rd.get("created_at")
                print(f"[DEBUG]   Row {rd.get('row')}: created_at={created_iso}")
                
                if not created_iso:
                    continue
                dt = _try_parse_dt(created_iso)
                if not dt:
                    print(f"[DEBUG]     -> 파싱 실패")
                    continue
                
                print(f"[DEBUG]     -> 파싱됨: {dt}")
                
                due = dt + timedelta(days=policy_days)
                violation = (now_utc > due)
                
                print(f"[DEBUG]     -> due={due}, now={now_utc}, violation={violation}")

                # 행 객체에 보존 계산 결과 주입
                rd.setdefault("retention", {})
                rd["retention"].update({
                    "policy_days": policy_days,
                    "due_at": due.isoformat(),
                    "violation": violation,
                })

                # 초과(만료)행이면 알림 큐에 적재
                if violation:
                    print(f"[DEBUG]     -> *** ALERT 적재 ***")
                    row_alerts.append({
                        "file": r.get("file"),
                        "row": rd.get("row"),
                        "created_at": created_iso,
                        "due_at": due.isoformat(),
                        # 알림에 표시할 최소 식별 정보(원하면 더 추가)
                        "row_key_fields": (rd.get("row_key_fields") or {
                            # 호환: CSV에 이런 헤더가 있으면 채워졌을 가능성 있음
                            "name_ko": (rd.get("entities") or {}).get("KR_NAME", [None])[0],
                            "email": (rd.get("entities") or {}).get("EMAIL_ADDRESS", [None])[0],
                            "phone": (rd.get("entities") or {}).get("PHONE_NUMBER", [None])[0],
                        }),
                        "entities": rd.get("entities"),
                    })

        # 파일 리포트에 alerts(파일별) 부착 + 전체 alerts 버킷에 합산
        if row_alerts:
            r["alerts"] = row_alerts
            alerts_bucket.extend(row_alerts)

        # 3) body.detected에 보존 디버그 키 주입(기존 유지)
        det = r.setdefault("body", {}).setdefault("detected", {}) or {}
        rb = r.get("retention_base")
        if rb is not None:
            det["__retention_base__"] = rb
        if r.get("retention_due_at") is not None:
            det["__retention_due_at__"] = r["retention_due_at"]
        if r.get("retention_violation") is not None:
            det["__retention_violation__"] = r["retention_violation"]

        # 4) console_like 재생성(기존 유지)
        key = r.get("file","")
        ctype = r.get("type","unknown")
        findings = {"values_text": det}
        category = (r.get("classification") or {}).get("category","none")
        reason   = (r.get("classification") or {}).get("reason","")
        r["console_like"] = build_console_like(key, ctype, findings, category, reason)

        enriched_reports.append(r)

    reports = enriched_reports

    # ===== 콘솔 출력 + results.json 저장 (기존 유지) =====
    console_blocks: List[str] = []
    for r in reports:
        det = r.get("body", {}).get("detected", {}) or {}
        has_pii = any(k for k in det.keys() if not str(k).startswith("__retention_"))
        has_ret = any(k in det for k in ("__retention_base__","__retention_due_at__","__retention_violation__"))
        if has_pii or has_ret:
            block = "\n" + r["console_like"]
            print(block)
            console_blocks.append(block)

    out_json_path.parent.mkdir(parents=True, exist_ok=True)
    out_json_path.write_text(json.dumps(reports, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n결과 JSON 저장: {out_json_path.resolve()}")

    # 추가 저장: 모든 파일의 만료행 합본 alerts.json
    base_dir = out_json_path.parent
    alerts_path = base_dir / "alerts.json"
    alerts_path.write_text(json.dumps(alerts_bucket, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Alerts 저장: {alerts_path.resolve()}  (rows={len(alerts_bucket)})")

    # ===== Front 전용 결과(results_front.json) 생성 (기존 + 만료행 카운트 추가) =====
    front_reports = []
    for r in reports:
        file = r.get("file")
        findings = r.get("body", {}).get("detected", {}) or {}
        category = r.get("classification", {}).get("category")
        reason = r.get("classification", {}).get("reason")
        saved_paths = r.get("classification", {}).get("saved_paths", {})
        expired_rows = len(r.get("alerts", []))  

        front_reports.append({
            "file": file,
            "source": _derive_source_label(file),
            "type": r.get("type"),
            "category": category,
            "reason": reason,
            "risk_hints": r.get("metadata", {}).get("risk_hints", {}),
            "stats": {
                "rows_scanned": r.get("body", {}).get("rows_scanned"),
                "total_entities": len(findings or {}),
                "unique_entity_types": list((findings or {}).keys()),
                "expired_rows": expired_rows,  
            },
            "entities": {
                ent: {
                    "count": len(vals),
                    "bucket": _bucket_for_entity(ent),
                    "values": vals,
                    "saved_path": saved_paths.get(ent)
                }
                for ent, vals in findings.items()
            }
        })

    front_path = base_dir / "results_front.json"
    front_path.write_text(json.dumps(front_reports, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Front 결과 저장: {front_path.resolve()}")

    # 콘솔 사본 (기존 유지)
    console_path = base_dir / "results.console.txt"
    if console_blocks:
        console_path.write_text("\n".join(console_blocks) + "\n", encoding="utf-8")
    else:
        console_path.write_text("# 본문 탐지 결과가 있는 항목이 없어 콘솔 출력이 없습니다.\n", encoding="utf-8")
    print(f"콘솔 출력 사본 저장: {console_path.resolve()}")

    # 엔티티별 텍스트 저장 (기존 유지)
    for r in reports:
        body_detected: Dict[str, List[str]] = r.get("body", {}).get("detected", {}) or {}
        if not body_detected:
            continue
        safe_key = re.sub(r"[<>:\"\\|?*]", "", r.get("file", "unknown")).strip().replace("..", ".").strip("/")
        for ent, vals in body_detected.items():
            if not vals: continue
            bucket = _bucket_for_entity(ent)
            per_ent_path = base_dir / CLASSIFY_ROOT / bucket / f"{safe_key}__{ent}.txt"
            per_ent_path.parent.mkdir(parents=True, exist_ok=True)
            per_ent_content = [
                f"# Original key: {r['file']}",
                f"# Type: {r['type']}",
                f"# Entity: {ent}",
                "",
                "## Values",
            ] + [str(v) for v in vals]
            per_ent_path.write_text("\n".join(per_ent_content) + "\n", encoding="utf-8")

    # 리소스(source) 롤업 (기존 유지)
    by_source: Dict[str, Dict[str, Any]] = {}
    for r in reports:
        src_label = _derive_source_label(r.get("file","")) or "unknown"
        body = r.get("body", {}).get("detected", {}) or {}
        cat = (r.get("classification", {}) or {}).get("category", "none")
        rec = by_source.setdefault(src_label, {
            "files": set(),
            "category_counts": {},
            "entities": {}
        })
        rec["files"].add(r.get("file",""))
        rec["category_counts"][cat] = rec["category_counts"].get(cat, 0) + 1
        for ent, vals in body.items():
            if not vals: continue
            entrec = rec["entities"].setdefault(ent, {"bucket": _bucket_for_entity(ent), "values": set()})
            for v in vals:
                try:
                    entrec["values"].add(str(v))
                except Exception:
                    pass

    rollup = []
    for src, rec in by_source.items():
        ent_out = {}
        for ent, e in rec["entities"].items():
            ent_out[ent] = {
                "bucket": e["bucket"],
                "count": len(e["values"]),
                "unique_values": len(e["values"])
            }
        rollup.append({
            "source": src,
            "total_files": len(rec["files"]),
            "category_counts": rec["category_counts"],
            "entities": ent_out
        })
    by_source_path = base_dir / "results_front_by_source.json"
    by_source_path.write_text(json.dumps(rollup, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"리소스 요약 저장: {by_source_path.resolve()}")

    # (선택) 리소스별 통합 텍스트 아카이브 (기존 유지)
    for src, rec in by_source.items():
        safe_src = re.sub(r"[^\w\-\.]+", "_", src or "unknown")
        for ent, e in rec["entities"].items():
            bucket = e["bucket"]
            out_dir = base_dir / "classified_by_source" / safe_src / bucket
            out_dir.mkdir(parents=True, exist_ok=True)
            out_file = out_dir / f"__ALL__{safe_src}__{ent}.txt"
            try:
                out_file.write_text("\n".join(sorted(e["values"])) + "\n", encoding="utf-8")
            except Exception:
                pass

# =========================================================
# 13) 페이로드 전개
# =========================================================
def _maybe_flatten_embedded_json_text(blob: Dict[str,Any]) -> Optional[List[Dict[str,Any]]]:
    try:
        text = (blob.get("content") or {}).get("text", "")
        if (not text) or (not text.strip().startswith(("[", "{"))):
            return None

        parsed = json.loads(text)
        if not isinstance(parsed, list):
            return None

        # 부모 key에서 .json 접미어 제거 후 prefix로 사용
        parent_key = (blob.get("key") or "")
        parent_prefix = re.sub(r"\.json$", "", parent_key)

        children = []
        for item in parsed:
            if not isinstance(item, dict):
                return None
            if "key" in item and "content" in item:
                # 내부 항목의 key 앞에 부모 경로를 붙여, 파일 라인에 풀경로가 찍히게 함
                child = dict(item)  # shallow copy
                child_key = str(child.get("key", "")).lstrip("/")
                child["key"] = f"{parent_prefix}/{child_key}"
                children.append(child)
            else:
                return None
        return children if children else None
    except Exception:
        return None

def preprocess_payload(payload: List[Dict[str,Any]]) -> List[Dict[str,Any]]:
    """
    입력 리스트를 받아, '본문이 내부 JSON 리스트'인 항목은 내부 key별로 전개하여 반환.
    그렇지 않은 항목은 그대로 유지.
    """
    result: List[Dict[str,Any]] = []
    for blob in payload:
        children = _maybe_flatten_embedded_json_text(blob)
        if children:
            # 외부 컨테이너(blob)는 건너뛰고, 내부 항목들을 채택
            result.extend(children)
        else:
            result.append(blob)
    return result

# =========================================================
# 14) CLI
# =========================================================
if __name__ == "__main__":
    import argparse
    import json
    from pathlib import Path
    from datetime import datetime, timedelta  # ← enrich_with_policy에서 사용

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

    # 내부 JSON 리스트 전개
    worklist = preprocess_payload(payload)

    # 분석 실행
    reports = [analyze_one_blob(b) for b in worklist]

    from pathlib import Path
    organize_and_save(reports, Path(args.output))

    print(f"[ok] 결과 저장: {Path(args.output).resolve()}")