# -*- coding: utf-8 -*-
import re
from typing import List, Optional
from presidio_analyzer import Pattern, PatternRecognizer, RecognizerResult
from .common_lexicon import adjust_topic_score, win_has_any, with_particles

class PipaSexLifeLexiconRecognizer(PatternRecognizer):
    """
    PIPA: SENSITIVE_SEX_LIFE (sexual life/orientation).
    - '성생활' 단어 단독은 민감정보로 확정하지 않음
    - 주변에 상담/기록/사실/경험/이력/문제/고민/내용 등의 컨텍스트가 있을 때만 통과
    - 성적지향/피임/임신/성병 등은 강하게 직접 매칭
    """

    # 강한 패턴들: 지향/임신/피임/성병/검사/진단
    _strong_terms = [
        Pattern("orientation",  r"(성적\s*지향|동성애|이성애|양성애|무성애)", 0.9),
        Pattern("pregnancy",    r"(임신|산전|산후|출산\s*계획|임신\s*계획)",   0.8),
        Pattern("contracept",   r"(피임|콘돔|경구\s*피임약|사후\s*피임)",      0.8),
        Pattern("sti_terms",    r"(성병|성\s*매개\s*감염|매독|임질|클라미디아|HPV|HIV)", 0.85),
    ]

    # 일반 '성생활' 헤드(단독으론 약하게) + 컨텍스트 트리거 근접 시에만 통과
    _head = with_particles(r"성\s*생활|성\s*관계|성\s*경험")
    _head_pat = Pattern("sex_head", _head, 0.4)  # 기본은 약함(컨텍스트 필요)

    # 컨텍스트 트리거(근접 시 가중)
    _ctx_triggers = [
        r"(상담|문의|지도|조언|교육)", r"(기록|메모|노트|문서|서류|차트)",
        r"(사실|내역|이력|경험|진술|보고)", r"(문제|고민|불편|증상|부작용)",
        r"(관련|에\s*대한|에\s*관한|내용)"
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="KOREAN_PIPA_SEX_LIFE",
            patterns=[*self._strong_terms, self._head_pat],
            context=["sex", "sexual", "성", "성생활", "지향", "임신", "피임", "성병"],
            supported_language=["ko", "en"],
        )
        # 미리 컴파일해두고, span_text에 대해 직접 판별
        self._head_re = re.compile(self._head, re.IGNORECASE)
        self._strong_res = [(p.name, re.compile(p.regex, re.IGNORECASE)) for p in self._strong_terms]

    def analyze(  # type: ignore[override]
        self,
        text: str,
        entities: Optional[List[str]] = None,
        nlp_artifacts=None,
    ) -> List[RecognizerResult]:
        # 기본 정규식 매칭(스팬만 얻어오고, 어떤 패턴인지는 우리가 직접 판별)
        base_results = super().analyze(text, entities, nlp_artifacts) or []
        out: List[RecognizerResult] = []

        for r in base_results:
            span_text = text[r.start:r.end]

            # 1) 강한 패턴에 해당하는지: span_text가 어떤 strong 정규식에라도 매칭되면 strong 케이스
            is_strong = any(regex.search(span_text) for _, regex in self._strong_res)

            if is_strong:
                raw = max(float(r.score or 0.0), 0.8)
                score = adjust_topic_score(span_text, raw)
                out.append(RecognizerResult(r.entity_type, r.start, r.end, score, analysis_explanation=None))
                continue

            # 2) '성생활/성관계/성경험' 헤드인지 확인
            if self._head_re.search(span_text):
                has_ctx = win_has_any(text, r.start, r.end, self._ctx_triggers, radius=40)
                if not has_ctx:
                    # 단순 언급은 드롭(민감정보로 확정 X)
                    continue
                raw = max(float(r.score or 0.0), 0.7)  # 컨텍스트가 있으니 상향
                # 근접 문맥에 대한 감쇄 적용
                win = text[max(0, r.start - 40): min(len(text), r.end + 40)]
                score = adjust_topic_score(win, raw)
                out.append(RecognizerResult(r.entity_type, r.start, r.end, score, analysis_explanation=None))
                continue

            # 3) 기타는 보수적으로
            score = adjust_topic_score(span_text, float(r.score or 0.0))
            if score >= 0.3:
                out.append(RecognizerResult(r.entity_type, r.start, r.end, score, analysis_explanation=None))

        return out
