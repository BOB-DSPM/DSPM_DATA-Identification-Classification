# -*- coding: utf-8 -*-
"""
KoreanPersonalNameRecognizer
- 성 1 + 이름 1~3 (한글)
- 복성(남궁, 제갈, 선우, 독고, 사공, 서문, 황보, ...) + 이름 1~2
- 중간점(·), 하이픈(-), 공백 변이 허용
- (선택) 한자 병기: 김민수(金民洙)
- 주변 문맥 가산점(님/씨/과장/대표/서명/연락처 등)
- 블랙리스트/일반명사 감점
"""

from __future__ import annotations
from typing import List, Optional, Sequence, Set
import regex as re

from presidio_analyzer import Pattern, PatternRecognizer, RecognizerResult

DEFAULT_SURNAMES: Sequence[str] = """
가 강 고 공 곽 구 권 김
나 남 노
도 동
류 리 림
마 문 민
박 반 방 배 백 변 범
서 석 선 설 성 소 손 송 신 심
안 양 엄 여 연 염 오 우 원 유 윤
이 임
장 전 정 조 주 진
차 채 천 최 추 탁
하 한 허 현 홍 황
""".split()

DEFAULT_COMPOUND_SURNAMES: Sequence[str] = """
남궁 제갈 선우 독고 사공 서문 황보
""".split()

DEFAULT_BLACKLIST_TERMS: Sequence[str] = """
주식회사 유한회사 회사 부서 팀 고객센터 개인정보 다운로드 계정 아이디 비밀번호 관리
서울시 경기도 대한민국 주소 전화번호 팍스 팩스 홈페이지 웹사이트 사용자 서비스 상품 모델
버전 로그 에러 오류 경로 파일 문서 내역 접수 처리 님 씨 과장 차장 부장 대표 사장 전무 상무 본부장 팀장 교수 박사 연락처 수신 발신 서명 참조 결재 결제 담당
""".split()

# 한글 이름 주변에서 자주 등장하는 문맥 앵커 단어들
DEFAULT_CONTEXT_ANCHORS = [
    "수신", "참조", "작성자", "담당자", "이름", "성명", "보낸이", "받는이",
    "대표", "부장", "차장", "과장", "대리", "주임", "팀장", "원장", "교수",
    "박사", "변호사", "기자", "작가", "교사", "선생", "의사", "간호사", "연구원",
    "입력자", "등록자", "기안자", "승인자", "검토자"
]

def _normalize_tokens(seq: Sequence[str]) -> Sequence[str]:
    """
    콤마/공백/특수문자 제거 → 한글/영문/숫자만 남김. 빈 토큰 제거.
    예: '김,' → '김'
    """
    out = []
    for s in (seq or []):
        t = re.sub(r"[^\p{Hangul}A-Za-z0-9]", "", s or "")
        if t:
            out.append(t)
    return out


class KoreanPersonalNameRecognizer(PatternRecognizer):
    """KR_NAME: 한글 한국인 이름 인식기 (성씨 사전 + 패턴 + 문맥 스코어링)"""

    # 한글/한자/구분자/패턴
    HANGUL = r"[가-힣]"
    HANJA = r"[一-龥㐀-䶵㇀-㇣]"  # 필요시 확장대역 추가
    SEP = r"(?:\s|·|-)?"           # 공백/중간점/하이픈 허용(옵션)

    # 후보 패턴(한자 병기 옵션)
    WITH_HANJA = rf"(?:\s*\((?:{HANJA}|\s)+\))?"

    def __init__(
        self,
        surnames: Optional[Sequence[str]] = None,
        compound_surnames: Optional[Sequence[str]] = None,
        blacklist_terms: Optional[Sequence[str]] = None,
        context_anchors: Optional[Sequence[str]] = None,
        supported_language: Optional[Sequence[str]] = None,
        **kwargs,
    ):
        # 토큰 정규화(콤마/특수문자 제거) 적용
        self.surnames: Set[str] = set(_normalize_tokens(surnames or DEFAULT_SURNAMES))
        self.compound_surnames: Set[str] = set(_normalize_tokens(compound_surnames or DEFAULT_COMPOUND_SURNAMES))
        self.blacklist: Set[str] = set(blacklist_terms or DEFAULT_BLACKLIST_TERMS)
        self.anchors: Sequence[str] = context_anchors or DEFAULT_CONTEXT_ANCHORS

        # 정규식 구성
        compound_group = "|".join(map(re.escape, sorted(self.compound_surnames, key=len, reverse=True)))
        HANGUL = self.HANGUL
        SEP = self.SEP
        WITH_HANJA = self.WITH_HANJA

        # (A) 성1 + 이름1~3
        core = rf"(?P<surname>{HANGUL})(?P<given>{HANGUL}{{1,3}})"

        # (B) 복성 + 이름1~2
        compound = rf"(?P<surname>(?:{compound_group}))(?P<given>{HANGUL}{{1,2}})"

        # (C) 변이 허용(공백/중간점/하이픈 섞임)
        variants = rf"(?P<surname>(?:{compound_group}|{HANGUL})){SEP}(?P<given>{HANGUL}(?:{SEP}{HANGUL}){{0,2}})"

        # (D) 최종 후보 + (선택) 한자 병기
        candidate = rf"(?:{compound}|{core}|{variants}){WITH_HANJA}"

        patterns = [Pattern(name="kr_name_candidate", regex=candidate, score=0.01)]
        super().__init__(
            supported_entity="KR_NAME",
            supported_language="en",   # ← AnalyzerEngine이 language="en"로 돌기 때문에 'en'로 고정
            patterns=patterns,
            **kwargs,
        )
        try:
            self.supported_languages = ["en", "ko"]
        except Exception:
            pass

    # 간단 스코어링 규칙
    def _score_candidate(self, text: str, start: int, end: int, sname: str) -> float:
        score = 0.0

        # --- 성씨 매칭 가산/감점 ---
        if sname in self.compound_surnames:
            score += 4
        elif (len(sname) == 1) and (sname in self.surnames):
            score += 3
        else:
            score -= 2

        window_l = max(0, start - 24)
        window_r = min(len(text), end + 24)
        window = text[window_l:window_r]

        # --- 블랙리스트 감점: 앵커 단어는 감점 예외 ---
        anchor_set = set(self.anchors)
        if any(term and (term not in anchor_set) and term in window for term in self.blacklist):
            score -= 4

        # --- 앵커 가산(문맥 신호) ---
        for a in self.anchors:
            if a and a in window:
                score += 1

        # --- 호칭 근접 가산: 매치 오른쪽 0~3자에 '님' 또는 '씨'가 오면 +1 ---
        right3 = text[end:end+3]
        if re.search(r"(님|씨)", right3):
            score += 1

        # --- 한자 병기 가산 ---
        if re.search(self.HANJA, window):
            score += 2

        # --- URL/이메일/경로 감점(오탐 방지) ---
        if re.search(r"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})", window):
            score -= 5
        if re.search(r"(https?://|www\.)", window):
            score -= 5
        if re.search(r"[/\\][\w.\-_/]+", window):
            score -= 3

        # --- 스케일링 → 0~1 (소폭 상향 오프셋) ---
        conf = max(0.0, min(1.0, 0.35 + 0.1 * score))
        return conf

    def analyze(  # type: ignore[override]
        self,
        text: str,
        entities: List[str],
        nlp_artifacts=None
    ) -> List[RecognizerResult]:
        results: List[RecognizerResult] = []
        pattern = self.patterns[0].regex

        for m in re.finditer(pattern, text):
            start, end = m.span()
            sname = m.groupdict().get("surname", "")
            raw = text[start:end]

            # --- 성씨 하드 필터: 1글자 성인데 사전에 없으면 스킵 ---
            if len(sname) == 1 and sname not in self.surnames:
                continue

            # --- 최소 길이 필터: 구분자/한자 제거 후 3자 미만이면 스킵 ---
            core = re.sub(r"[·\-\s]", "", raw)             # 구분자 제거
            core = re.sub(self.WITH_HANJA, "", core)       # (선택) 한자 병기 제거
            if len(core) < 3:
                continue

            # --- 앵커 단어 자체 매칭 제외(수신/참조/서명 등) ---
            if core in set(self.anchors):
                continue

            conf = self._score_candidate(text, start, end, sname)
            if conf >= 0.5:
                results.append(
                    RecognizerResult(
                        entity_type=self.supported_entities[0],
                        start=start,
                        end=end,
                        score=conf,
                    )
                )

        # 중복 제거 없이 그대로 반환 (사용자 요청)
        return results

