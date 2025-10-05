# -*- coding: utf-8 -*-
from presidio_analyzer import Pattern, PatternRecognizer


class KoreanAddressRecognizer(PatternRecognizer):
    """
    Heuristic patterns for KR postal-style addresses.
    Multiple patterns with different strengths; scores set per Pattern.
    """

    # Strong: [시/도] [구/군] [로/길] [number] ...
    _addr_strong = Pattern(
        name="kr_addr_strong",
        regex=r"(?:서울|부산|대구|인천|광주|대전|울산|세종|제주|경기|강원|충북|충남|전북|전남|경북|경남)\S*\s+"
              r"(?:[가-힣]+(?:구|군))\s+"
              r"[가-힣0-9]+(?:로|길)\s+\d+(?:[-\s]?\d+)*(?:\s*\S*)?",
        score=0.8,
    )

    # Medium: [시/도] [구/군] ... (without explicit 로/길)
    _addr_medium = Pattern(
        name="kr_addr_medium",
        regex=r"(?:서울특별시|서울시|서울|경기도|인천광역시|부산광역시|대구광역시|광주광역시|대전광역시|울산광역시)\s+"
              r"[가-힣]+(?:구|군)\s+[가-힣0-9\s]+",
        score=0.65,
    )

    # Lite: "동|읍|면 + 번지" style
    _addr_lite = Pattern(
        name="kr_addr_lite",
        regex=r"[가-힣]+(?:동|읍|면)\s+\d+(?:[-\s]?\d+)*호?",
        score=0.55,
    )

    def __init__(self) -> None:
        super().__init__(
            supported_entity="KOREAN_ADDRESS",
            patterns=[self._addr_strong, self._addr_medium, self._addr_lite],
            context=["주소", "address", "거주지", "거소", "위치", "location"],
            supported_language="ko",  # ← 리스트가 아니라 "ko" 단일 문자열
        )
