# -*- coding: utf-8 -*-
from presidio_analyzer import Pattern
import re
from pathlib import Path

# --- Lexicon loader ----------------------------------------------------------
def load_lexicon(path: str) -> list[str]:
    """
    TSV format: term [TAB] weight? [TAB] notes?
    Only 'term' is required; weight/notes are ignored here.
    """
    terms: list[str] = []
    p = Path(path)
    if not p.exists():
        # Fail safe: allow empty list so the app still runs
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

# --- Context heuristics ------------------------------------------------------
_NEGATION_RE = re.compile(r"(아니|아님|없음|무관|비해당|미가입|not\b|no\b|never\b|without\b)")
_POLICY_RE   = re.compile(r"(정의|법령|제\d+조|고시|기준|해당\s*없음|참고)")
_WS          = re.compile(r"\s+")

def normalize_ws(s: str) -> str:
    return _WS.sub(" ", s).strip()

def adjust_topic_score(snippet: str, score: float) -> float:
    """Lower scores for negations / policy definitions to reduce false positives."""
    s = normalize_ws(snippet)
    if _NEGATION_RE.search(s):
        score *= 0.7
    if _POLICY_RE.search(s):
        score *= 0.85
    return max(0.0, min(1.0, score))

# --- Optional: ICD-10 pattern (for health) -----------------------------------
ICD10_PATTERN = Pattern(
    name="ICD10_CODE",
    # e.g., E11.9, C34, F32.0 (A–Z except U reserved in WHO core)
    regex=r"\b([A-TV-Z][0-9][0-9AB](?:\.[0-9A-TV-Z]{1,4})?)\b",
    score=0.55,
)

def icd10_boost_around(text: str, start: int, end: int, base_score: float, radius: int = 60) -> float:
    """If an ICD-10-like code is nearby, boost the health score a bit."""
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    window = text[left:right]
    if re.search(ICD10_PATTERN.regex, window):
        return max(base_score, 0.75)
    return base_score
