# recognizers/korean_id_recognizer.py
# 고유식별정보(주민등록번호/외국인등록번호/여권번호/운전면허번호) 인식기
import regex as re
from presidio_analyzer import EntityRecognizer, RecognizerResult

# 주민등록/외국인등록: YYMMDD-ABCDEFG or YYMMDDABCDEFG
# 주민 7번째 자리 1~4, 외국인 5~8 (단순 규칙)
_RRN_RE = re.compile(r"(?<!\d)(\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])[-]?[1-4]\d{6}(?!\d)")
_FRN_RE = re.compile(r"(?<!\d)(\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])[-]?[5-8]\d{6}(?!\d)")

# 여권번호(간이): 1문자+8숫자 또는 2문자+7숫자
# 실제 국적별 포맷 다양하나 한국 여권은 보통 1문자+8숫자(M12345678)로 충분
_PASSPORT_RE = re.compile(r"(?<![A-Z0-9])[A-Z]\d{8}(?![A-Z0-9})|(?<![A-Z0-9])[A-Z]{2}\d{7}(?![A-Z0-9])")

# 운전면허번호(간이): 12-34-567890-12 또는 12-34-567890-1 등 일부 변형 허용
_DL_RE = re.compile(r"(?<!\d)\d{2}-\d{2}-\d{6}-\d{1,2}(?!\d)")

def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)

def _rrn_checksum_valid(s: str) -> bool:
    """주민/외국인등록 13자리 체크섬(간이)"""
    d = _digits(s)
    if len(d) != 13:
        return False
    nums = list(map(int, d))
    weights = [2,3,4,5,6,7,8,9,2,3,4,5]
    tot = sum(n*w for n, w in zip(nums[:12], weights))
    check = (11 - (tot % 11)) % 10
    return check == nums[12]

class KoreanIdRecognizer(EntityRecognizer):
    """
    지원 엔티티:
      - KR_RRN            : 주민등록번호
      - KR_FRN            : 외국인등록번호
      - KR_PASSPORT       : 여권번호(간이)
      - KR_DRIVER_LICENSE : 운전면허번호(간이)
    """
    expected_confidence_level = 0.85

    def __init__(self):
        super().__init__(supported_entities=["KR_RRN","KR_FRN","KR_PASSPORT","KR_DRIVER_LICENSE"],
                         supported_language="ko")

    def analyze(self, text, entities, nlp_artifacts=None):
        results = []

        # 주민등록
        for m in _RRN_RE.finditer(text):
            val = m.group(0)
            score = 0.95 if _rrn_checksum_valid(val) else 0.60
            results.append(RecognizerResult("KR_RRN", m.start(), m.end(), score))

        # 외국인등록
        for m in _FRN_RE.finditer(text):
            val = m.group(0)
            score = 0.90 if _rrn_checksum_valid(val) else 0.60
            results.append(RecognizerResult("KR_FRN", m.start(), m.end(), score))

        # 여권
        for m in _PASSPORT_RE.finditer(text):
            results.append(RecognizerResult("KR_PASSPORT", m.start(), m.end(), 0.75))

        # 운전면허
        for m in _DL_RE.finditer(text):
            results.append(RecognizerResult("KR_DRIVER_LICENSE", m.start(), m.end(), 0.80))

        return results
