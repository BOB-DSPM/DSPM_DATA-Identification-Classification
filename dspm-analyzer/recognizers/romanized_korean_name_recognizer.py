# -*- coding: utf-8 -*-
"""
RomanizedKoreanNameRecognizer
- "Kim Min-su", "Minsoo Kim", "Lee Ji-eun" 등 로마자 한국식 이름 후보
- 대소문 혼합 선호, 하이픈/중간점(·) 허용
- 전부 대문자(KIM MIN SU) 등은 약어/ID로 감점
- 한국식 성씨 로마자 사전과 매칭 가산
"""

from __future__ import annotations
from typing import List, Optional, Sequence, Set
import regex as re

from presidio_analyzer import Pattern, PatternRecognizer, RecognizerResult


ROMA_SURNAMES: Sequence[str] = """
Kim Lee Rhee Yi Park Bak Pak Choi Choe
Jung Jeong Chong Cho Jo Jang Chang
Kang Gang Yoon Yun Ryu Yoo You
Lim Im Shim Sim Shin Sin Son Song
Han Hwang Kwon Gwon Koo Ku Gu
Baek Paik Back Hong Heo Hur Seo Suh
""".split()


class RomanizedKoreanNameRecognizer(PatternRecognizer):
    """KR_NAME_ROMA: 로마자 한국식 이름 인식기"""

    # 로마자 단어(첫글자 대문자, 내부 소문자, 하이픈/중간점 허용)
    ROMA_WORD = r"[A-Z][a-z]+(?:[-·][A-Z][a-z]+)?"

    # 두 단어 조합 (Given Surname / Surname Given 모두 후보로 수집)
    ROMA_PAIR = rf"(?P<w1>{ROMA_WORD})\s+(?P<w2>{ROMA_WORD})"

    def __init__(
        self,
        roma_surnames: Optional[Sequence[str]] = None,
        supported_language: Optional[Sequence[str]] = None,
        **kwargs,
    ):
        self.roma_surnames: Set[str] = set(roma_surnames or ROMA_SURNAMES)
        patterns = [Pattern(name="kr_name_roma_pair", regex=self.ROMA_PAIR, score=0.01)]
        super().__init__(
            supported_entity="KR_NAME_ROMA",
            supported_language=supported_language or ["en", "ko"],
            patterns=patterns,
            **kwargs,
        )

    def _score(self, w1: str, w2: str, window: str) -> float:
        score = 0.0

        # (1) 성씨 사전 매칭(앞/뒤 어느 쪽이든)
        if w1 in self.roma_surnames or w2 in self.roma_surnames:
            score += 3

        # (2) 전부 대문자/약어 의심 감점
        if re.fullmatch(r"[A-Z]{2,}", w1) or re.fullmatch(r"[A-Z]{2,}", w2):
            score -= 3

        # (3) 이메일/URL/경로 감점
        if re.search(r"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})", window):
            score -= 5
        if re.search(r"(https?://|www\.)", window):
            score -= 5
        if re.search(r"[/\\][\w.\-_/]+", window):
            score -= 3

        # (4) 주변 앵커(라틴 문맥)
        anchors = ["Name", "Signed", "Attn", "From", "To", "Cc", "Mr.", "Ms.", "Dr."]
        if any(a in window for a in anchors):
            score += 1

        return max(0.0, min(1.0, 0.3 + 0.1 * score))

    def analyze(  # type: ignore[override]
        self,
        text: str,
        entities: List[str],
        nlp_artifacts=None
    ) -> List[RecognizerResult]:
        results: List[RecognizerResult] = []
        for m in re.finditer(self.patterns[0].regex, text):
            start, end = m.span()
            w1, w2 = m.group("w1"), m.group("w2")

            window_l = max(0, start - 24)
            window_r = min(len(text), end + 24)
            window = text[window_l:window_r]

            conf = self._score(w1, w2, window)
            if conf >= 0.5:
                results.append(
                    RecognizerResult(
                        entity_type=self.supported_entities[0],
                        start=start,
                        end=end,
                        score=conf,
                    )
                )

        results = self.remove_duplicates(text, results)
        return results
