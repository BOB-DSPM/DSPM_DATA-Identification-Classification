# common_lexicon.py (추가/보강)
# -*- coding: utf-8 -*-
from presidio_analyzer import Pattern
import re
from pathlib import Path

def load_lexicon(path: str) -> list[str]:
    terms: list[str] = []
    p = Path(path)
    if not p.exists():
        return terms
    with p.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            term = line.split("\t", 1)[0].strip()
            if term:
                terms.append(term)
    return terms

# --- 문맥/부정 처리 -----------------------------------------------------------
_NEGATION_RE = re.compile(r"(아니|아님|없음|무관|비해당|미가입|미해당|불가|거부|부정|not\b|no\b|never\b|without\b)")
_POLICY_RE   = re.compile(r"(정의|법령|제\d+조|고시|기준|해당\s*없음|참고|예시|설명)")
_WS          = re.compile(r"\s+")

def normalize_ws(s: str) -> str:
    return _WS.sub(" ", s).strip()

def adjust_topic_score(snippet: str, score: float) -> float:
    s = normalize_ws(snippet)
    if _NEGATION_RE.search(s):
        score *= 0.6
    if _POLICY_RE.search(s):
        score *= 0.8
    return max(0.0, min(1.0, score))

def window(text: str, start: int, end: int, radius: int) -> str:
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    return text[left:right]

def win_has_any(text: str, start: int, end: int, terms: list[str], radius: int = 40) -> bool:
    win = window(text, start, end, radius)
    return any(re.search(t, win) for t in terms)

def with_particles(word: str) -> str:
    # 간단한 조사/형태 변형 허용 (…은/는/이/가/을/를/에/에서/관련/에 대한/에 관한)
    return rf"{word}(?:\s*(?:은|는|이|가|을|를|의|에|에서))?(?:\s*(?:관련|에\s*대한|에\s*관한))?"

# --- (선택) ICD-10 패턴 --------------------------------------------------------
ICD10_PATTERN = Pattern(
    name="ICD10_CODE",
    regex=r"\b([A-TV-Z][0-9][0-9AB](?:\.[0-9A-TV-Z]{1,4})?)\b",
    score=0.55,
)

def icd10_boost_around(text: str, start: int, end: int, base_score: float, radius: int = 60) -> float:
    left = max(0, start - radius); right = min(len(text), end + radius)
    if re.search(ICD10_PATTERN.regex, text[left:right]):
        return max(base_score, 0.75)
    return base_score
