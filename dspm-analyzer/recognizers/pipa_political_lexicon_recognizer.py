# -*- coding: utf-8 -*-
from presidio_analyzer import Pattern, PatternRecognizer


class PipaPoliticalLexiconRecognizer(PatternRecognizer):
    """
    PIPA: SENSITIVE_POLITICAL (political opinions/party/affiliation).
    """

    _political_terms = [
        Pattern("political_view", r"(정치적\s*견해|정치\s*성향|보수\s*성향|진보\s*성향|중도\s*성향)", 0.75),
        Pattern("political_party", r"(정당|당원|당적|당비|당대표|당선)", 0.7),
        Pattern("party_membership", r"(정당\s*가입|정당\s*탈당|당\s*가입|당\s*탈당)", 0.7),
        Pattern("election_terms", r"(선거|투표|공천|출마|지지율)", 0.55),
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="KOREAN_PIPA_POLITICAL",
            patterns=self._political_terms,
            context=["political", "정치", "정당", "정치견해", "정치성향"],
            supported_language="ko",  # ← 교정
        )
