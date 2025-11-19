# recognizers/korean_rrn_recognizer.py
# 한국 주민등록번호 인식기 (체크섬 검증 포함)
import regex as re
from presidio_analyzer import Pattern, PatternRecognizer, RecognizerResult

# YYMMDD-ABCDEFG 또는 YYMMDDABCDEFG
RRN_PATTERN = r"(?<!\d)(\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])[-]?[1-4]\d{6}(?!\d)"
_rrn_re = re.compile(RRN_PATTERN)

def rrn_checksum_valid(s: str) -> bool:
    """
    주민등록번호 13자리 체크:
      가중치: [2,3,4,5,6,7,8,9,2,3,4,5]
      check = (11 - (sum % 11)) % 10
    """
    digits = re.sub(r"\D", "", s)
    if len(digits) != 13:
        return False
    nums = list(map(int, digits))
    weights = [2,3,4,5,6,7,8,9,2,3,4,5]
    tot = sum(n*w for n, w in zip(nums[:12], weights))
    check = (11 - (tot % 11)) % 10
    return check == nums[12]

class KoreanRRNRecognizer(PatternRecognizer):
    """
    - 정규식 + 체크섬 검증
    - 체크섬 통과 시 score 0.95, 아니면 0.60 (의심값)
    """
    def __init__(self):
        super().__init__(
            supported_entity="KR_RRN",
            patterns=[Pattern("rrn_like", RRN_PATTERN, 0.60)],
            supported_language=["ko","en"],
        )

    def analyze(self, text, entities, nlp_artifacts=None):
        res = []
        for m in _rrn_re.finditer(text):
            span = m.group(0)
            score = 0.95 if rrn_checksum_valid(span) else 0.60
            res.append(RecognizerResult("KR_RRN", m.start(), m.end(), score))
        return res
