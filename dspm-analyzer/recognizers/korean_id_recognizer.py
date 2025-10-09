# -*- coding: utf-8 -*-
# 고유식별정보(주민등록번호/외국인등록번호/여권번호/운전면허번호) 인식기
import regex as re
from datetime import datetime
from presidio_analyzer import EntityRecognizer, RecognizerResult

# --- 하이픈/공백·마스킹 정규화 ---
_HYPHENS = dict.fromkeys(map(ord, "\u2010\u2011\u2012\u2013\u2014\u2015"), ord('-'))

def _normalize_text(s: str) -> str:
    # 유니코드 하이픈 -> '-', 전각 공백/일반 공백을 단일 공백으로
    s = (s or "").translate(_HYPHENS)
    s = re.sub(r"[ \u00A0\u2000-\u200B\u3000]+", " ", s)
    return s

def _digits(s: str) -> str:
    return re.sub(r"\D", "", s or "")

# --- 날짜 유효성(캘린더) + 세기 추정 ---
def _valid_rrn_yyyymmdd(yy: str, mm: str, dd: str, seventh: str) -> bool:
    """
    7번째 자리로 세기 추정:
      1,2,5,6 -> 1900~1999
      3,4,7,8 -> 2000~2099
    """
    y = int(yy)
    if seventh in "1256":
        year = 1900 + y
    elif seventh in "3478":
        year = 2000 + y
    else:
        return False
    try:
        datetime(year, int(mm), int(dd))
        return True
    except ValueError:
        return False

def _rrn_checksum_valid(s: str) -> bool:
    """주민/외국인등록 13자리 체크섬"""
    d = _digits(s)
    if len(d) != 13:
        return False
    nums = list(map(int, d))
    weights = [2,3,4,5,6,7,8,9,2,3,4,5]
    tot = sum(n*w for n, w in zip(nums[:12], weights))
    check = (11 - (tot % 11)) % 10
    return check == nums[12]

# --- 정규식 ---
# 주민/외국인등록: YYMMDD[-\s]?ABCDEFG(총 13자리). 하이픈/공백 허용 + 마스킹 문자 허용.
_MASK = r"[*●•◦∙·]"
_RRN_CORE = (
    r"(\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])"
    r"(?:-| )?"              # 하이픈 또는 단일 공백 허용
    r"([1-4])"               # 7번째
    r"(?:\d|%s){6}" % _MASK  # 뒤 6자리에 마스킹 섞여도 허용
)
_FRN_CORE = (
    r"(\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])"
    r"(?:-| )?"
    r"([5-8])"
    r"(?:\d|%s){6}" % _MASK
)

_RRN_RE = re.compile(r"(?<!\d)" + _RRN_CORE + r"(?!\d)")
_FRN_RE = re.compile(r"(?<!\d)" + _FRN_CORE + r"(?!\d)")

# 여권: 영문1 + 숫자8 (예: M12345678)
_PASSPORT_RE = re.compile(r"(?<![A-Z0-9])[A-Z]\d{8}(?![A-Z0-9])")

# 운전면허: 정확히 2-2-6-2
_DL_RE = re.compile(r"(?<!\d)\d{2}-\d{2}-\d{6}-\d{2}(?!\d)")

# --- 컨텍스트 감점(오탐 완화) ---
_CTX_NEG = {"dob", "birth", "생년월일", "출생", "주소", "address"}

def _context_score(t: str, span_start: int, span_end: int) -> float:
    window = 32
    left = max(0, span_start - window)
    right = min(len(t), span_end + window)
    ctx = t[left:right].lower()
    score = 0.0
    for s in _CTX_NEG:
        if s in ctx:
            score -= 0.25
    return score

class KoreanIdRecognizer(EntityRecognizer):
    """
    지원 엔티티:
      - KR_RRN            : 주민등록번호
      - KR_FRN            : 외국인등록번호
      - KR_PASSPORT       : 여권번호(1문자+8숫자)
      - KR_DRIVER_LICENSE : 운전면허번호(2-2-6-2 형식)
    """
    expected_confidence_level = 0.5

    def __init__(self):
        super().__init__(
            supported_entities=["KR_RRN","KR_FRN","KR_PASSPORT","KR_DRIVER_LICENSE"],
            supported_language="en",  # 엔진 언어 필터 우회
        )
        self.supported_languages = ["ko","en"]

    def analyze(self, text, entities, nlp_artifacts=None):
        t = _normalize_text(text)
        results = []

        # 주민등록
        for m in _RRN_RE.finditer(t):
            raw = m.group(0)
            digits_only = _digits(raw)
            if len(digits_only) != 13:
                continue
            yy, mm, dd, seventh = m.group(1), m.group(2), m.group(3), m.group(4)
            cal_ok = _valid_rrn_yyyymmdd(yy, mm, dd, seventh)
            chk_ok = _rrn_checksum_valid(digits_only)
            base = 0.60 + (0.20 if cal_ok else 0.0) + (0.20 if chk_ok else 0.0)
            score = min(0.99, base + _context_score(t, m.start(), m.end()))
            results.append(RecognizerResult("KR_RRN", m.start(), m.end(), score))

        # 외국인등록
        for m in _FRN_RE.finditer(t):
            raw = m.group(0)
            digits_only = _digits(raw)
            if len(digits_only) != 13:
                continue
            yy, mm, dd, seventh = m.group(1), m.group(2), m.group(3), m.group(4)
            cal_ok = _valid_rrn_yyyymmdd(yy, mm, dd, seventh)
            chk_ok = _rrn_checksum_valid(digits_only)
            base = 0.55 + (0.20 if cal_ok else 0.0) + (0.15 if chk_ok else 0.0)
            score = min(0.97, base + _context_score(t, m.start(), m.end()))
            results.append(RecognizerResult("KR_FRN", m.start(), m.end(), score))

        # 여권
        for m in _PASSPORT_RE.finditer(t):
            results.append(RecognizerResult("KR_PASSPORT", m.start(), m.end(), 0.85))

        # 운전면허
        for m in _DL_RE.finditer(t):
            results.append(RecognizerResult("KR_DRIVER_LICENSE", m.start(), m.end(), 0.85))

        return results
