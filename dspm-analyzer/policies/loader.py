# dspm-analyzer/policies/loader.py
from __future__ import annotations
import csv, re
from dataclasses import dataclass

@dataclass
class PolicyRow:
    policy_id: str
    file_name: str
    system_name: str | None
    dept: str | None
    purpose: str | None
    retention_raw: str
    retention_days: int | None   # 고정기간(일)
    retention_type: str          # 'fixed' | 'event' | 'other'
    retention_event: str | None  # 'graduation' 등

RE_YEAR = re.compile(r'(\d+)\s*년')
RE_MONTH = re.compile(r'(\d+)\s*개월?')

EVENT_MAP = {
    '졸업 시': 'graduation',
    '목적달성 시': 'purpose_done',
    '재직기간 종료 시': 'employment_end',
    '준영구': 'permanent',
    '영구': 'permanent',
    '기타': 'other',
}

def _parse_retention(s: str) -> tuple[int|None, str, str|None]:
    s = (s or '').strip()
    if not s:
        return None, 'other', None
    y = RE_YEAR.search(s); m = RE_MONTH.search(s)
    if y or m:
        days = (int(y.group(1))*365 if y else 0) + (int(m.group(1))*30 if m else 0)
        return days, 'fixed', None
    for k, v in EVENT_MAP.items():
        if k in s:
            return None, 'event', v
    return None, 'other', None

def load_policies(csv_path: str) -> list[PolicyRow]:
    out: list[PolicyRow] = []
    with open(csv_path, encoding='utf-8-sig') as f:
        rdr = csv.DictReader(f)
        for i, row in enumerate(rdr, start=1):
            # === 네 CSV 헤더명에 정확히 맞춤 ===
            file_name = (row.get('개인정보파일의 명칭') or '').strip()
            purpose   = (row.get('개인정보파일 운영목적 ') or '').strip()  # 주의: 끝 공백 포함 헤더
            dept      = (row.get('부서명') or '').strip()
            system    = (row.get('개인정보의 처리방법') or '').strip()
            retention = (row.get('개인정보의 보유기간') or '').strip()

            # 빈 보조열(예: Unnamed: 6)은 무시

            days, rtype, event = _parse_retention(retention)
            out.append(PolicyRow(
                policy_id=f"POL-{i:04d}",
                file_name=file_name,
                system_name=system or None,
                dept=dept or None,
                purpose=purpose or None,
                retention_raw=retention,
                retention_days=days,
                retention_type=rtype,
                retention_event=event
            ))
    return out
