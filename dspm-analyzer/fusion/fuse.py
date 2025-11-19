# fusion/fuse.py
from collections import defaultdict

# Weights configurable via YAML
DEFAULT_WEIGHTS = {
  "pattern": 0.6,      # Presidio (regex/pattern) score
  "lexicon": 0.5,      # deny-list recognizer score
  "classifier": 0.7,   # ML probability
  "context": 0.2       # extra from heuristics
}

THRESHOLDS = {
  "ID_NUMBER": 0.75,
  "SENSITIVE_HEALTH": 0.7,
  "SENSITIVE_BELIEF": 0.7,
  "SENSITIVE_POLITICAL": 0.7,
  "SENSITIVE_UNION": 0.7,
  "SENSITIVE_SEX_LIFE": 0.7,
  # … other entities per your tolerance
}

def fuse_scores(components):
    # components: dict e.g., {"pattern":0.8, "lexicon":0.6, "classifier":0.55, "context":0.1}
    num, den = 0.0, 0.0
    for k, v in components.items():
        w = DEFAULT_WEIGHTS.get(k, 0)
        num += w * v
        den += w
    return num/den if den>0 else 0.0

def decide(entity, fused_score):
    return fused_score >= THRESHOLDS.get(entity, 0.7)
