# -*- coding: utf-8 -*-
from presidio_analyzer import Pattern, PatternRecognizer


class PipaSexLifeLexiconRecognizer(PatternRecognizer):
    """
    PIPA: SENSITIVE_SEX_LIFE (sexual life/orientation).
    """

    _sexlife_terms = [
        Pattern("sex_life", r"(성생활|성\s*생활|성\s*관계|성\s*경험)", 0.8),
        Pattern("orientation", r"(성적\s*지향|동성애|이성애|양성애|무성애)", 0.75),
        Pattern("privacy_related", r"(임신|피임|성병|산전|산후)", 0.6),
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="KOREAN_PIPA_SEX_LIFE",
            patterns=self._sexlife_terms,
            context=["sex", "sexual", "성", "성생활", "지향", "임신"],
            supported_language="ko",  
        )
