# -*- coding: utf-8 -*-
import regex as re
from presidio_analyzer import EntityRecognizer, RecognizerResult

# 한국 주소 패턴(영문 로/길 허용)
_ADDR_RE = re.compile(r"""
\b(
 (?:서울|부산|대구|인천|광주|대전|울산|세종|
    제주|경기|강원|충북|충남|전북|전남|경북|경남)
 (?:특별시|광역시|특별자치시|도)?
 \s*
 (?:[가-힣]{1,12}(?:시|군|구))?
 \s*
 (?:[가-힣0-9]{1,20}(?:읍|면|동|리))?
 \s*
 (?:[A-Za-z가-힣0-9]{1,30}(?:로|길))
 \s*
 (?:\d{1,4}(?:-\d{1,4})?)?
 (?:\s*(?:번지|지|동|호|층)\s*\d{1,4})?
)
\b
""", re.VERBOSE)

class KoreanAddressRecognizer(EntityRecognizer):
    expected_confidence_level = 0.5
    def __init__(self):
        super().__init__(
            supported_entities=["KOREAN_ADDRESS"],
            supported_language=["ko","en"],
        )
    def analyze(self, text, entities, nlp_artifacts=None):
        if not text: return []
        results = []
        for m in _ADDR_RE.finditer(text):
            results.append(RecognizerResult("KOREAN_ADDRESS", m.start(), m.end(), 0.80))
        return results
