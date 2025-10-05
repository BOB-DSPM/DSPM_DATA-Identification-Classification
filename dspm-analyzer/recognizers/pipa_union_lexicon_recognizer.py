# -*- coding: utf-8 -*-
from presidio_analyzer import Pattern, PatternRecognizer


class PipaUnionLexiconRecognizer(PatternRecognizer):
    """
    PIPA: SENSITIVE_UNION (labor union membership/activities).
    """

    _union_terms = [
        Pattern("union_core",       r"(노조|노동조합|조합원|노조원)", 0.85),
        Pattern("union_membership", r"(노조\s*(가입|탈퇴)|조합\s*(가입|탈퇴)|가입\s*이력|탈퇴\s*이력)", 0.9),
        Pattern("union_activity",   r"(단체협약|파업|교섭|쟁의\s*행위|노사\s*협의|조합\s*활동)", 0.75),
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="KOREAN_PIPA_UNION",
            patterns=self._union_terms,
            context=["union", "노조", "노동", "조합", "조합원"],
            supported_language="ko",  
        )
