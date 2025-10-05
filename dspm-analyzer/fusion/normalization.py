# fusion/normalization.py
import re, unicodedata

FULLWIDTH_DIGITS = str.maketrans("０１２３４５６７８９", "0123456789")

ZERO_WIDTH = dict.fromkeys(i for i in range(sys.maxunicode)
                           if unicodedata.category(chr(i)) == "Cf")

EMAIL_DEOBF_RE = [
  (re.compile(r"(?i)\s*(?:\(|\[)?\s*at\s*(?:\)|\])?\s*"), "@"),
  (re.compile(r"(?i)\s*(?:\(|\[)?\s*dot\s*(?:\)|\])?\s*"), "."),
]

def normalize_text(s: str) -> str:
    if not isinstance(s, str): s = str(s)
    s = s.translate(ZERO_WIDTH)             # remove zero-width
    s = s.translate(FULLWIDTH_DIGITS)       # ３→3
    for rx, rep in EMAIL_DEOBF_RE: s = rx.sub(rep, s)
    s = unicodedata.normalize("NFKC", s)    # unify Unicode forms
    return s.strip()
