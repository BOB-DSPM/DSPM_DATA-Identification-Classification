# -*- coding: utf-8 -*-
from presidio_analyzer import Pattern, PatternRecognizer


class PipaHealthLexiconRecognizer(PatternRecognizer):
    """
    PIPA: SENSITIVE_HEALTH (health status/diagnosis/medical records).
    Includes ICD-10 pattern and common health terms.
    """

    # ICD-10: A00–Z99 with optional .x
    _icd10 = Pattern(
        name="icd10_code",
        regex=r"\b[A-TV-Z][0-9]{2}(?:\.[0-9A-TV-Z]{1,4})?\b",
        score=0.9,
    )

    _health_terms = [
        Pattern("medical_terms_strong", r"(진단|처방|의무기록|건강검진|병력|질병|환자)", 0.75),
        Pattern("common_conditions", r"(당뇨|고혈압|우울증|불안장애|편두통|천식|기관지염)", 0.65),
        Pattern("pregnancy_medical", r"(임신\s*기록|산전|산후|산부인과)", 0.65),
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="KOREAN_PIPA_HEALTH",
            patterns=[self._icd10, *self._health_terms],
            context=["건강", "헬스", "의료", "진단", "처방", "기록", "medical", "health"],
            supported_language="ko",  # ← 교정
        )
