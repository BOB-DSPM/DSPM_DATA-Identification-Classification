# -*- coding: utf-8 -*-
from presidio_analyzer import Pattern, PatternRecognizer


class KoreanRRNRecognizer(PatternRecognizer):
    """
    Detects Korean Resident Registration Number (주민등록번호) - RRN-like strings.
    Uses two common forms:
      - YYMMDD-XXXXXXX
      - YYMMDDXXXXXXX
    We assign scores on the Pattern objects (no global score in super()).
    """

    # Strong pattern: with dash
    _rrn_with_dash = Pattern(
        name="rrn_with_dash",
        regex=r"(?<!\d)(\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])-[1-4]\d{6}(?!\d)",
        score=0.9,
    )

    # Alternate: without dash (more false-positive risk)
    _rrn_no_dash = Pattern(
        name="rrn_no_dash",
        regex=r"(?<!\d)(\d{2})(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])[1-4]\d{6}(?!\d)",
        score=0.75,
    )

    def __init__(self) -> None:
        super().__init__(
            supported_entity="KOREAN_RRN",
            patterns=[self._rrn_with_dash, self._rrn_no_dash],
            context=["주민등록", "주민번호", "rrn", "resident registration", "national id"],
            supported_language="ko",  # ← 리스트가 아니라 단일 문자열
        )
