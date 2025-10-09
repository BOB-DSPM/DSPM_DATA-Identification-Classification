# -*- coding: utf-8 -*-
from presidio_analyzer import Pattern, PatternRecognizer
import re

class PipaHealthLexiconRecognizer(PatternRecognizer):
    """
    PIPA: SENSITIVE_HEALTH (health status/diagnosis/medical records).
    - 강한 신호: ICD-10 코드 (A00–Z99, U 제외) -> score 높게
    - 일반 신호: 건강/의료 관련 한글 키워드
    """
    # ICD-10: A00–Z99 (U 블록 제외), 선택적 .하위코드 1~4자
    _icd10 = Pattern(
        name="icd10_code",
        regex=r"\b[A-TV-Z][0-9]{2}(?:\.[0-9A-TV-Z]{1,4})?\b",
        score=0.90,
    )

    _health_terms = [
        # 강한 의료 용어
        Pattern("medical_terms_strong", r"(진단|처방|의무기록|건강검진|병력|의학적\s*소견)", 0.80),
        # 흔한 만성질환·증상
        Pattern("common_conditions", r"(당뇨|고혈압|우울증|편두통|천식|기관지염|만성질환)", 0.70),
        # 내원/지도/권고 등 병원 컨텍스트
        Pattern("clinical_context", r"(내원|외래|입원|퇴원|복약\s*지도|운동요법\s*권고|생활습관\s*지도)", 0.65),
        # 임신/산전·산후
        Pattern("pregnancy_medical", r"(임신\s*기록|산전\s*검사|산후\s*관리|산부인과)", 0.70),
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="KOREAN_PIPA_HEALTH",
            patterns=[self._icd10, *self._health_terms],
            context=["건강", "의료", "진단", "처방", "기록", "medical", "health", "환자", "내원"],
            supported_language=["ko", "en"],
        )
