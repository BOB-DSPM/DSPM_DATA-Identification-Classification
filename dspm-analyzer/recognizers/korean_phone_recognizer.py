# -*- coding: utf-8 -*-
from presidio_analyzer import Pattern, PatternRecognizer


class KoreanPhoneRecognizer(PatternRecognizer):
    """
    Detects KR phone numbers: mobile & landline in common formats.
    Scores are set per Pattern (no global score).
    """

    # Mobile: 010-1234-5678 / 010 1234 5678 / 01012345678 / +82 10 1234 5678
    _mobile_hyphen = Pattern(
        name="kr_mobile_hyphen",
        regex=r"(?<!\d)(?:\+?82[-.\s]?)?0?10[-.\s]?\d{3,4}[-.\s]?\d{4}(?!\d)",
        score=0.8,
    )

    _mobile_compact = Pattern(
        name="kr_mobile_compact",
        regex=r"(?<!\d)010\d{7,8}(?!\d)",
        score=0.7,
    )

    # Landline: 02-123-4567 / 02-1234-5678 / +82 2 777 4444
    _landline = Pattern(
        name="kr_landline",
        regex=r"(?<!\d)(?:\+?82[-.\s]?)?0?(?:2|[3-6][0-9])[-.\s]?\d{3,4}[-.\s]?\d{4}(?!\d)",
        score=0.65,
    )

    def __init__(self) -> None:
        super().__init__(
            supported_entity="KOREAN_PHONE",
            patterns=[self._mobile_hyphen, self._mobile_compact, self._landline],
            context=["연락처", "전화", "phone", "mobile", "contact", "tel", "핸드폰"],
            supported_language="ko",  # ← 리스트가 아니라 "ko" 단일 문자열
        )
