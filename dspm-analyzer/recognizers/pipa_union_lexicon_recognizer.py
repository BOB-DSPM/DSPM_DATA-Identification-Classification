# -*- coding: utf-8 -*-
from presidio_analyzer import Pattern, PatternRecognizer


class PipaUnionLexiconRecognizer(PatternRecognizer):
    """
    PIPA: SENSITIVE_UNION (labor union membership/activities).
    """

    _union_terms = [
        Pattern("union_core", r"(노조|노동조합|조합원|노조원)", 0.8),
        Pattern("union_membership", r"(노조\s*가입|노조\s*탈퇴|조합\s*가입|조합\s*탈퇴)", 0.75),
        Pattern("union_activity", r"(단체협약|파업|교섭|쟁의행위|노사협의)", 0.6),
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="KOREAN_PIPA_UNION",
            patterns=self._union_terms,
            context=["union", "노조", "노동", "조합", "조합원"],
            supported_language="ko",  
        )
