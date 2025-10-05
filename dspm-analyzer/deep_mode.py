# deep_mode.py
# -----------------------------------------------------------------------------
# Presidio + 커스텀 한국어 인식기(lexicon/규칙 기반) 통합 모드
# - 엔진: spaCy 영어 모델 1개만 사용(기본 en_core_web_lg, 미설치 시 sm로 폴백)
# - 커스텀 인식기는 정규식/사전 기반이라 영어 엔진 위에서도 한글 텍스트 탐지 가능
# - Presidio 언어 필터 통과를 위해 커스텀 인식기에 'en'을 런타임 추가
# - 호출: from deep_mode import deep_scan_text, list_loaded_recognizers
# -----------------------------------------------------------------------------

from __future__ import annotations
from typing import Iterable, List, Dict, Any, Tuple
import importlib
import json

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry, RecognizerResult

# === 설정값 =========================================================================
# 기본 엔진 모델(권장: en_core_web_lg). 없으면 en_core_web_sm로 자동 폴백됩니다.
SPACY_MODEL_PREFERRED = "en_core_web_lg"
SPACY_MODEL_FALLBACK  = "en_core_web_sm"

# 빌트인(EMAIL/PERSON/LOCATION/DATE_TIME 등)까지 쓰고 싶으면 True
LOAD_PREDEFINED = False

# 분석 임계값
DEFAULT_SCORE_THRESHOLD = 0.5
# ====================================================================================

# --- 커스텀 인식기 -------------------------------------------------------------
from recognizers.korean_rrn_recognizer import KoreanRRNRecognizer
from recognizers.korean_phone_recognizer import KoreanPhoneRecognizer
from recognizers.korean_address_recognizer import KoreanAddressRecognizer
from recognizers.pipa_belief_lexicon_recognizer import PipaBeliefLexiconRecognizer
from recognizers.pipa_political_lexicon_recognizer import PipaPoliticalLexiconRecognizer
from recognizers.pipa_union_lexicon_recognizer import PipaUnionLexiconRecognizer
from recognizers.pipa_health_lexicon_recognizer import PipaHealthLexiconRecognizer
from recognizers.pipa_sex_life_lexicon_recognizer import PipaSexLifeLexiconRecognizer

# --- 전역 싱글턴 ----------------------------------------------------------------
REGISTRY: RecognizerRegistry | None = None
ANALYZER: AnalyzerEngine | None = None


def _register_custom_recognizers(registry: RecognizerRegistry) -> None:
    """한국형/민감정보 커스텀 인식기 등록 + 언어 필터(en) 주입."""
    # 한국형 규칙/번호/주소/전화
    registry.add_recognizer(KoreanRRNRecognizer())
    registry.add_recognizer(KoreanPhoneRecognizer())
    registry.add_recognizer(KoreanAddressRecognizer())

    # PIPA 민감정보 Lexicon 인식기
    registry.add_recognizer(PipaBeliefLexiconRecognizer())
    registry.add_recognizer(PipaPoliticalLexiconRecognizer())
    registry.add_recognizer(PipaUnionLexiconRecognizer())
    registry.add_recognizer(PipaHealthLexiconRecognizer())
    registry.add_recognizer(PipaSexLifeLexiconRecognizer())

    # --- 언어 필터(en) 통과를 위해 ko 전용 인식기에 en도 주입 (양방향 세팅) ---
    for r in list(registry.recognizers):
        sl  = getattr(r, "supported_language",  None)
        sls = getattr(r, "supported_languages", None)

        # 현재 선언이 "ko" 또는 ["ko"] 계열이면 en 추가
        need_patch = False
        if isinstance(sl, str) and sl.lower() == "ko":
            newlangs = ["ko", "en"]
            need_patch = True
        elif isinstance(sls, (list, tuple, set)) and "ko" in sls and "en" not in sls:
            newlangs = list(sls) + ["en"]
            need_patch = True
        else:
            newlangs = None

        if need_patch and newlangs:
            # 일부 Presidio 버전은 한쪽 속성만 읽으므로 둘 다 세팅
            try: r.supported_language = "en"           # 단일 문자열도 설정
            except Exception: pass
            try: r.supported_languages = newlangs       # 리스트도 설정
            except Exception: pass

def _resolve_spacy_model() -> str:
    """선호 모델이 설치되어 있으면 사용, 아니면 소형(sm)으로 폴백."""
    try:
        importlib.import_module(SPACY_MODEL_PREFERRED)
        return SPACY_MODEL_PREFERRED
    except Exception:
        pass
    try:
        importlib.import_module(SPACY_MODEL_FALLBACK)
        print(f"[deep_mode] '{SPACY_MODEL_PREFERRED}' not found. Falling back to '{SPACY_MODEL_FALLBACK}'.")
        return SPACY_MODEL_FALLBACK
    except Exception as e:
        raise RuntimeError(
            f"Neither '{SPACY_MODEL_PREFERRED}' nor '{SPACY_MODEL_FALLBACK}' is installed.\n"
            f"Install with:\n"
            f"  python -m spacy download {SPACY_MODEL_PREFERRED}\n"
            f"  # or\n"
            f"  python -m spacy download {SPACY_MODEL_FALLBACK}"
        ) from e


def _build_singletons() -> None:
    """전역 REGISTRY/ANALYZER를 한 번만 생성."""
    global REGISTRY, ANALYZER
    if REGISTRY is not None and ANALYZER is not None:
        return

    from presidio_analyzer.nlp_engine import SpacyNlpEngine

    # 1) 레지스트리 구성
    REGISTRY = RecognizerRegistry()
    if LOAD_PREDEFINED:
        REGISTRY.load_predefined_recognizers()  # EMAIL/PERSON/LOCATION/DATE_TIME 등 빌트인
    _register_custom_recognizers(REGISTRY)

    # 2) spaCy 엔진: 영어 모델 1개만 로드
    model_name = _resolve_spacy_model()  # lg → sm 순으로 확인
    nlp_engine = SpacyNlpEngine(models=[  # ← 리스트 형식으로!
        {"lang_code": "en", "model_name": model_name}
    ])

    # 3) AnalyzerEngine 싱글턴
    ANALYZER = AnalyzerEngine(
        nlp_engine=nlp_engine,
        registry=REGISTRY,
        supported_languages=["en"],  # 엔진은 en만 사용
    )


def get_analyzer() -> AnalyzerEngine:
    """항상 전역 ANALYZER를 반환."""
    if ANALYZER is None:
        _build_singletons()
    assert ANALYZER is not None
    return ANALYZER


def list_loaded_recognizers() -> List[Dict[str, Any]]:
    """디버그용: 로드된 인식기, 언어, 엔터티 요약."""
    if REGISTRY is None:
        _build_singletons()
    assert REGISTRY is not None

    summary: List[Dict[str, Any]] = []
    for rec in REGISTRY.recognizers:
        try:
            langs = getattr(rec, "supported_language", None) or getattr(rec, "supported_languages", None)
            entities = getattr(rec, "supported_entities", None) or getattr(rec, "entities", None)
            summary.append({
                "name": rec.__class__.__name__,
                "langs": list(langs) if isinstance(langs, (list, tuple, set)) else langs,
                "entities": list(entities) if isinstance(entities, (list, tuple, set)) else entities,
            })
        except Exception:
            summary.append({
                "name": rec.__class__.__name__,
                "langs": "unknown",
                "entities": "unknown",
            })
    return summary


# --- 유틸 ----------------------------------------------------------------------
def _safe_text_slice(text: str, start: int, end: int) -> str:
    start = max(0, min(len(text), int(start)))
    end = max(start, min(len(text), int(end)))
    return text[start:end]


def _result_to_dict(text: str, r: RecognizerResult) -> Dict[str, Any]:
    return {
        "entity": r.entity_type,
        "start": r.start,
        "end": r.end,
        "text": _safe_text_slice(text, r.start, r.end),
        "score": float(getattr(r, "score", 0.0)),
        "analysis_explanation": getattr(r, "analysis_explanation", None),
    }


def _dedupe_results(items: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """(entity, start, end, text) 키로 중복 제거. score는 최대값 유지."""
    best: Dict[Tuple[str, int, int, str], Dict[str, Any]] = {}
    for it in items:
        k = (it["entity"], it["start"], it["end"], it["text"])
        prev = best.get(k)
        if prev is None or it.get("score", 0.0) > prev.get("score", 0.0):
            best[k] = it
    return list(best.values())


def _analyze_text(text: str) -> List[Dict[str, Any]]:
    """언어는 항상 en로 호출(엔진 안정성). 정규식 기반 커스텀 인식기는 한글도 잘 매칭됨."""
    analyzer = get_analyzer()
    try:
        results = analyzer.analyze(
            text=text,
            entities=None,
            language="en",  # 고정
            score_threshold=DEFAULT_SCORE_THRESHOLD,
        )
    except ValueError:
        results = []
    return [_result_to_dict(text, r) for r in results]


def deep_scan_text(text: str) -> Dict[str, Any]:
    """단일 호출: 분석 → 병합/중복제거 → 로더 정보까지 반환."""
    _ = get_analyzer()
    res = _analyze_text(text)
    merged = _dedupe_results(res)
    return {
        "language_results": {"en": res},
        "merged": merged,
        "loaded_recognizers": list_loaded_recognizers(),
    }


# --- CLI/디버그 ----------------------------------------------------------------
if __name__ == "__main__":
    sample = "진단: 당뇨(E11.9) 및 고혈압. 노동조합 조합원 가입. 정치적 견해 표명. 성생활 관련 상담."
    out = deep_scan_text(sample)

    print("[deep_mode] recognizers (loaded once):")
    for r in out["loaded_recognizers"]:
        print(f" - {r.get('name')}  langs={r.get('langs')}  entities={r.get('entities')}")

    print("\n[en results]")
    for r in out["language_results"]["en"]:
        print(f"  - {r['entity']:>28}  score={r['score']:.3f}  text='{r['text']}'")

    print("\n[merged (dedup)]")
    for r in out["merged"]:
        print(f"  - {r['entity']:>28}  score={r['score']:.3f}  text='{r['text']}'")
