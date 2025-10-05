# -*- coding: utf-8 -*-
from presidio_analyzer import Pattern, PatternRecognizer


class PipaPoliticalLexiconRecognizer(PatternRecognizer):
    """
    PIPA: SENSITIVE_POLITICAL (political opinions/party/affiliation).
    """

    # 패턴 배열 교체 예시
    _political_terms = [
        Pattern("political_view",   r"(정치적\s*견해|정치\s*성향|보수\s*성향|진보\s*성향|중도\s*성향)", 0.8),
        Pattern("party_status",     r"(정당\s*(가입|탈당)|당\s*(가입|탈당)|당원|당적|당비)", 0.85),
        Pattern("support_activity", r"(지지\s*(표명|선언)|후원\s*(회원|금)|캠페인\s*참여|유세\s*참여)", 0.7),
        Pattern("candidacy",        r"(출마|공천|예비후보|후보\s*등록)", 0.7),
        Pattern("election_terms",   r"(선거|투표|지지율|개표|득표)", 0.55),
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="KOREAN_PIPA_POLITICAL",
            patterns=self._political_terms,
            context=["political", "정치", "정당", "정치견해", "정치성향"],
            supported_language="ko",  # ← 교정
        )
