# -*- coding: utf-8 -*-
from presidio_analyzer import Pattern, PatternRecognizer


class PipaBeliefLexiconRecognizer(PatternRecognizer):
    """
    PIPA: SENSITIVE_BELIEF (ideas/beliefs/religion).
    Simple lexicon-based regex patterns with per-pattern scores.
    """

    _belief_terms = [
        Pattern("belief_religion", r"(종교|신앙|신념|무신론|유신론|불교|기독교|천주교|이슬람|힌두교)", 0.75),
        Pattern("belief_affiliation", r"(교회|성당|사찰|사원|신도)", 0.65),
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="KOREAN_PIPA_BELIEF",
            patterns=self._belief_terms,
            context=["belief", "religion", "신념", "종교", "사상"],
            supported_language="ko",  # ← 교정
        )
