# dspm-analyzer/policies/slug.py
import re, unicodedata

def slugify_ko_to_en(s: str) -> str:
    s = unicodedata.normalize('NFKD', (s or '').strip())
    s = re.sub(r'[\s/_.]+', '-', s)
    s = re.sub(r'[^a-zA-Z0-9\-]+', '', s).strip('-').lower()
    return f'pii-{s}' if not s.startswith('pii-') else s
