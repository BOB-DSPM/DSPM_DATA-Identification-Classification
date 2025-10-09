# -*- coding: utf-8 -*-
from __future__ import annotations
from typing import List
from presidio_analyzer import PatternRecognizer, RecognizerResult
import regex as re

# 하이픈(일반/긴 대시) 통일용: [-–—]
H = r"[-–—]"

class KoreanBankAccountRecognizer(PatternRecognizer):
    """
    국내 은행 계좌번호(하이픈 포함) 패턴 인식기.

    요구사항:
      - 총 '숫자 자리수' 기준으로 10~14자리
      - 하이픈(일반/긴 대시 등) 반드시 1개 이상 포함
      - (정책) CSV에서는 main.py에서 헤더 힌트 있을 때만 수용

    구현 메모:
      - 정규식 단계: '숫자와 하이픈으로 이루어진 덩어리'를 잡아오되, 하이픈이 최소 1개는 존재
      - 후처리 단계: 하이픈 제거 후 숫자 자리수를 10~14 범위로 필터
      - 컨텍스트 단어(계좌/입금/account 등) 근접 시 점수 보정
    """

    # 후보: 숫자+하이픈으로 이루어진 시퀀스(하이픈 1개 이상 강제)
    #  예: 123-45-678901, 123–45–6789—01, 12-3456789012 등
    _BASE_RX = re.compile(
        rf"(?<!\d)(?=[\d{H}]*{H})(?:\d+{H})+\d+(?!\d)"
    )

    _CTX = ("계좌", "계좌번호", "입금", "은행", "account", "acct", "account_no", "bank_account")

    def __init__(self):
        super().__init__(
            supported_entity="KR_BANK_ACCOUNT",
            supported_language="ko",
        )
        # Presidio 내부 언어 필터 우회를 위해 en도 허용
        try:
            self.supported_languages = ["ko", "en"]
        except Exception:
            pass

    @staticmethod
    def _digits_len(s: str) -> int:
        return len(re.sub(r"\D", "", s or ""))

    @staticmethod
    def _has_hyphen(s: str) -> bool:
        return bool(re.search(H, s or ""))

    @staticmethod
    def _score(raw: str, ctx: str, start: int, end: int) -> float:
        # 기본점수
        score = 0.6

        # 하이픈 개수(최대 3개까지 가산)
        hyphens = re.findall(H, raw or "")
        score += min(3, len(hyphens)) * 0.05  # +0.00 ~ +0.15

        # 컨텍스트 근접 보정(+0.1): 매치 좌우 24자
        L = max(0, start - 24)
        R = min(len(ctx), end + 24)
        window = ctx[L:R].lower()
        if any(t in window for t in (w.lower() for w in KoreanBankAccountRecognizer._CTX)):
            score += 0.1

        return max(0.0, min(0.95, score))

    # PatternRecognizer.analyze 오버라이드
    def analyze(self, text: str, entities: List[str] | None = None, nlp_artifacts=None) -> List[RecognizerResult]:
        if not text:
            return []

        results: List[RecognizerResult] = []
        for m in self._BASE_RX.finditer(text):
            start, end = m.span()
            raw = text[start:end]

            # 필수 조건: 하이픈 존재 + 숫자 자리수 10~14
            if not self._has_hyphen(raw):
                continue
            if not (10 <= self._digits_len(raw) <= 14):
                continue

            sc = self._score(raw, text, start, end)
            results.append(
                RecognizerResult(
                    entity_type="KR_BANK_ACCOUNT",
                    start=start,
                    end=end,
                    score=sc,
                )
            )

        return results
