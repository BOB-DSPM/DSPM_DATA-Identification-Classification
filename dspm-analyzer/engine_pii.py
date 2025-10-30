# -*- coding: utf-8 -*-
"""
engine_pii.py
- Presidio + 커스텀 인식기(PIPA + 고유식별) 항상 활성화
- 한글 민감어 매칭 강화를 위해 fallback 인식기(관대한 정규식) 추가
- ISO 날짜/일시 인식기 추가 (YYYY-MM-DD, YYYY/MM/DD, YYYY.MM.DD, YYYYMMDD, ISO8601)
- main.py와의 호환을 위해 analyze_text() 제공 (presidio_scan=analyze_text)
"""

from __future__ import annotations
import importlib
from typing import List, Dict, Any

from presidio_analyzer import (
    AnalyzerEngine,
    RecognizerRegistry,
    RecognizerResult,
    PatternRecognizer,
    Pattern,
)

# ============== 설정 ==============
_SPACY_PREFERRED = "en_core_web_lg"
_SPACY_FALLBACK = "en_core_web_sm"
_DEFAULT_THRESH = 0.5

REGISTRY: RecognizerRegistry | None = None
ENGINE: AnalyzerEngine | None = None


# ============== spaCy 모델 확인 ==============
def _resolve_spacy() -> str:
    try:
        importlib.import_module(_SPACY_PREFERRED)
        return _SPACY_PREFERRED
    except Exception:
        pass

    try:
        importlib.import_module(_SPACY_FALLBACK)
        print(f"[engine_pii] fallback spaCy model -> '{_SPACY_FALLBACK}'")
        return _SPACY_FALLBACK
    except Exception as e:
        raise RuntimeError(
            "Install spaCy model:\n"
            f"  python -m spacy download {_SPACY_PREFERRED}\n"
            "or\n"
            f"  python -m spacy download {_SPACY_FALLBACK}"
        ) from e


# ============== Fallback PIPA 인식기들(관대한 한글 패턴) ==============
class FallbackPoliticalRecognizer(PatternRecognizer):
    def __init__(self):
        patt = r"(정치적\s*견해|정치적\s*성향|정당\s*(지지|가입)|보수|진보)"
        super().__init__(
            supported_entity="KOREAN_PIPA_POLITICAL",
            patterns=[Pattern("p_political", patt, 1.0)],
            supported_language=["ko", "en"],
        )


class FallbackUnionRecognizer(PatternRecognizer):
    def __init__(self):
        patt = r"(노동조합|노조|조합원|노동\s*조합)"
        super().__init__(
            supported_entity="KOREAN_PIPA_UNION",
            patterns=[Pattern("p_union", patt, 1.0)],
            supported_language=["ko", "en"],
        )


class FallbackHealthRecognizer(PatternRecognizer):
    def __init__(self):
        patt = r"(진단|질병|건강정보|의무기록|건강검진|우울증|당뇨|고혈압|임상\s*소견)"
        super().__init__(
            supported_entity="KOREAN_PIPA_HEALTH",
            patterns=[Pattern("p_health", patt, 1.0)],
            supported_language=["ko", "en"],
        )


class FallbackSexLifeRecognizer(PatternRecognizer):
    def __init__(self):
        patt = r"(성생활\s*상담|성생활|성적\s*지향|성\s*지향|성관계|임신|성\s*관련\s*상담)"
        super().__init__(
            supported_entity="KOREAN_PIPA_SEX_LIFE",
            patterns=[Pattern("p_sexlife", patt, 1.0)],
            supported_language=["ko", "en"],
        )


class FallbackBeliefRecognizer(PatternRecognizer):
    def __init__(self):
        patt = r"(종교|불교|기독교|천주교|무신론|신념)"
        super().__init__(
            supported_entity="KOREAN_PIPA_BELIEF",
            patterns=[Pattern("p_belief", patt, 1.0)],
            supported_language=["ko", "en"],
        )


# ============== ISO 날짜/일시 인식기 ==============
ISO_DATE_PATTERNS = [
    # 구분자 있는 형식: YYYY-MM-DD, YYYY/MM/DD, YYYY.MM.DD (한 자리 일자 포함)
    Pattern(
        name="iso_ymd_sep",
        regex=r"\b(1[89]|20)\d{2}[-/.](0?[1-9]|1[0-2])[-/.](0?[1-9]|[12]\d|3[01])\b",
        score=0.7,
    ),
    # 구분자 있는 형식 (한 자리 월도 지원): YYYY-M-D
    Pattern(
        name="iso_ymd_sep_flexible",
        regex=r"\b(1[89]|20)\d{2}[-/.]([1-9]|0[1-9]|1[0-2])[-/.]([1-9]|0[1-9]|[12]\d|3[01])\b",
        score=0.7,
    ),
    # 구분자 없는 형식: YYYYMMDD (두 자리 고정)
    Pattern(
        name="iso_ymd_compact",
        regex=r"\b(1[89]|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\b",
        score=0.6,
    ),
    # ISO 8601 datetime 형식
    Pattern(
        name="iso_datetime",
        regex=r"\b(1[89]|20)\d{2}-[01]\d-[0-3]\d[T ][0-2]\d:[0-5]\d(?::[0-5]\d)?(?:\.\d+)?(?:Z|[+-][0-2]\d:?[0-5]\d)?\b",
        score=0.8,
    ),
    # 짧은 형식: YY-MM-DD, YY/MM/DD, YY.MM.DD (한 자리 일자 포함)
    Pattern(
        name="short_ymd_sep",
        regex=r"\b\d{2}[-/.](0?[1-9]|1[0-2])[-/.](0?[1-9]|[12]\d|3[01])\b",
        score=0.5,
    ),
    # 역순 형식: DD-MM-YYYY, DD/MM/YYYY (한 자리 일자 포함)
    Pattern(
        name="dmy_format",
        regex=r"\b(0?[1-9]|[12]\d|3[01])[-/.](0?[1-9]|1[0-2])[-/.](1[89]|20)\d{2}\b",
        score=0.6,
    ),
    # 미국식: MM-DD-YYYY, MM/DD/YYYY (한 자리 일자 포함)
    Pattern(
        name="mdy_format",
        regex=r"\b(0?[1-9]|1[0-2])[-/.](0?[1-9]|[12]\d|3[01])[-/.](1[89]|20)\d{2}\b",
        score=0.6,
    ),
]


class IsoDateRecognizer(PatternRecognizer):
    def __init__(self):
        super().__init__(
            supported_entity="DATE_TIME",
            name="iso_date_recognizer",
            patterns=ISO_DATE_PATTERNS,
            supported_language="all",
        )



# ============== 커스텀 인식기 등록 ==============
def _register_custom(reg: RecognizerRegistry):
    # 고유식별정보
    from recognizers.korean_id_recognizer import KoreanIdRecognizer
    reg.add_recognizer(KoreanIdRecognizer())

    # 한국 주소 인식기
    try:
        from recognizers.korean_address_recognizer import KoreanAddressRecognizer
        reg.add_recognizer(KoreanAddressRecognizer())
    except Exception:
        pass

    # 한국 은행 계좌 인식기
    try:
        from recognizers.korean_bank_account_recognizer import KoreanBankAccountRecognizer
        reg.add_recognizer(KoreanBankAccountRecognizer())
    except Exception:
        pass

    # 한국 이름 인식기 2종 등록
    try:
        from recognizers.korean_personal_name_recognizer import KoreanPersonalNameRecognizer
        reg.add_recognizer(KoreanPersonalNameRecognizer())  # entity: KR_NAME
    except Exception as e:
        print(f"[engine_pii] warn: KoreanPersonalNameRecognizer 등록 실패: {e}")

    try:
        from recognizers.romanized_korean_name_recognizer import RomanizedKoreanNameRecognizer
        reg.add_recognizer(RomanizedKoreanNameRecognizer())  # entity: KR_NAME_ROMA
    except Exception as e:
        print(f"[engine_pii] warn: RomanizedKoreanNameRecognizer 등록 실패: {e}")

    # PIPA 인식기(외부 모듈 시도 → 실패 시 fallback)
    try:
        from recognizers.pipa_belief_lexicon_recognizer import PipaBeliefLexiconRecognizer
        reg.add_recognizer(PipaBeliefLexiconRecognizer())
    except Exception:
        reg.add_recognizer(FallbackBeliefRecognizer())

    try:
        from recognizers.pipa_political_lexicon_recognizer import PipaPoliticalLexiconRecognizer
        reg.add_recognizer(PipaPoliticalLexiconRecognizer())
    except Exception:
        reg.add_recognizer(FallbackPoliticalRecognizer())

    try:
        from recognizers.pipa_union_lexicon_recognizer import PipaUnionLexiconRecognizer
        reg.add_recognizer(PipaUnionLexiconRecognizer())
    except Exception:
        reg.add_recognizer(FallbackUnionRecognizer())

    try:
        from recognizers.pipa_health_lexicon_recognizer import PipaHealthLexiconRecognizer
        reg.add_recognizer(PipaHealthLexiconRecognizer())
    except Exception:
        reg.add_recognizer(FallbackHealthRecognizer())

    try:
        from recognizers.pipa_sex_life_lexicon_recognizer import PipaSexLifeLexiconRecognizer
        reg.add_recognizer(PipaSexLifeLexiconRecognizer())
    except Exception:
        reg.add_recognizer(FallbackSexLifeRecognizer())

    # ko 전용 인식기에 en도 넣어 프레지디오 언어필터 우회
    for r in list(reg.recognizers):
        sl = getattr(r, "supported_language", None)
        sls = getattr(r, "supported_languages", None)
        newlangs = None

        if isinstance(sl, str) and sl.lower() == "ko":
            newlangs = ["ko", "en"]
        elif isinstance(sls, (list, tuple, set)) and "ko" in sls and "en" not in sls:
            newlangs = list(sls) + ["en"]

        if newlangs:
            try:
                r.supported_language = "en"
            except Exception:
                pass
            try:
                r.supported_languages = newlangs
            except Exception:
                pass

    # ISO 날짜 인식기 등록
    reg.add_recognizer(IsoDateRecognizer())


def _build_engine():
    global REGISTRY, ENGINE
    if REGISTRY and ENGINE:
        return

    from presidio_analyzer.nlp_engine import SpacyNlpEngine

    REGISTRY = RecognizerRegistry()
    _register_custom(REGISTRY)

    model = _resolve_spacy()
    nlp = SpacyNlpEngine(models=[{"lang_code": "en", "model_name": model}])
    ENGINE = AnalyzerEngine(nlp_engine=nlp, registry=REGISTRY, supported_languages=["en"])


# ============== 퍼블릭 API ==============
def _safe_slice(t: str, s: int, e: int) -> str:
    s = max(0, min(len(t), int(s)))
    e = max(s, min(len(t), int(e)))
    return t[s:e]


def _dedupe_hits(hits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    best = {}
    for h in hits:
        k = (h.get("entity"), h.get("start"), h.get("end"), h.get("text"))
        if k not in best:
            best[k] = h
    return list(best.values())


def analyze_text(text: str) -> Dict[str, Any]:
    """
    main.py가 기대하는 형태로 결과 제공:
    {"merged": [ {entity, start, end, text, score}, ... ] }
    """
    if not text:
        return {"merged": []}

    _build_engine()

    try:
        results: List[RecognizerResult] = ENGINE.analyze(
            text=text,
            entities=None,
            language="en",
            score_threshold=_DEFAULT_THRESH,
        )
    except ValueError:
        results = []

    merged: List[Dict[str, Any]] = []
    for r in results:
        merged.append(
            {
                "entity": r.entity_type,
                "start": r.start,
                "end": r.end,
                "text": _safe_slice(text, r.start, r.end),
                "score": float(getattr(r, "score", 0.0)),
            }
        )
    merged = _dedupe_hits(merged)
    return {"merged": merged}


# 기존 코드와의 호환/가독성 위해 alias 제공
def presidio_scan(text: str) -> List[Dict[str, Any]]:
    return analyze_text(text).get("merged", [])


def list_loaded_recognizers() -> List[Dict[str, Any]]:
    _build_engine()
    out: List[Dict[str, Any]] = []
    for rec in REGISTRY.recognizers:
        langs = getattr(rec, "supported_language", None) or getattr(rec, "supported_languages", None)
        ents = getattr(rec, "supported_entities", None) or getattr(rec, "entities", None)
        out.append(
            {
                "name": rec.__class__.__name__,
                "langs": list(langs) if isinstance(langs, (list, tuple, set)) else langs,
                "entities": list(ents) if isinstance(ents, (list, tuple, set)) else ents,
            }
        )
    return out


# ============== 자가 테스트 ==============
if __name__ == "__main__":
    _build_engine()
