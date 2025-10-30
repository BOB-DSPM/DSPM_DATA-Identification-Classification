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

# 더 관대한 정규식 (공백, 특수문자 무시)
RE_YEAR = re.compile(r'(\d+)\s*년', re.UNICODE)
RE_MONTH = re.compile(r'(\d+)\s*개?월', re.UNICODE)

EVENT_MAP = {
    '졸업 시': 'graduation',
    '목적달성 시': 'purpose_done',
    '재직기간 종료 시': 'employment_end',
    '준영구': 'permanent',
    '영구': 'permanent',
    '기타': 'other',
}

def _parse_retention(s: str) -> tuple[int|None, str, str|None]:
    """
    보유기간 문자열 파싱
    예: "5년" -> (1825, 'fixed', None)
        "3개월" -> (90, 'fixed', None)
        "졸업 시" -> (None, 'event', 'graduation')
    """
    s = (s or '').strip()
    if not s:
        return None, 'other', None
    
    # 연도와 개월 모두 추출
    years = 0
    months = 0
    
    y_match = RE_YEAR.search(s)
    if y_match:
        years = int(y_match.group(1))
    
    m_match = RE_MONTH.search(s)
    if m_match:
        months = int(m_match.group(1))
    
    # 연도나 개월이 있으면 일수로 변환
    if years > 0 or months > 0:
        days = (years * 365) + (months * 30)
        print(f"[DEBUG] _parse_retention: '{s}' -> years={years}, months={months}, days={days}")
        return days, 'fixed', None
    
    # 이벤트 기반 보유기간
    for k, v in EVENT_MAP.items():
        if k in s:
            return None, 'event', v
    
    return None, 'other', None

def load_policies(csv_path: str) -> list[PolicyRow]:
    out: list[PolicyRow] = []
    with open(csv_path, encoding='utf-8-sig') as f:
        rdr = csv.DictReader(f)
        for i, row in enumerate(rdr, start=1):
            # CSV 헤더명 (공백 주의)
            file_name = (row.get('개인정보파일의 명칭') or '').strip()
            
            # 두 가지 가능성 모두 시도 (공백 있는 것/없는 것)
            purpose = (row.get('개인정보파일 운영목적 ') or 
                      row.get('개인정보파일 운영목적') or '').strip()
            dept = (row.get('부서명') or '').strip()
            system = (row.get('개인정보의 처리방법') or '').strip()
            retention = (row.get('개인정보의 보유기간') or '').strip()

            print(f"[DEBUG] load_policies row {i}: file_name='{file_name}', retention='{retention}'")

            days, rtype, event = _parse_retention(retention)
            
            policy = PolicyRow(
                policy_id=f"POL-{i:04d}",
                file_name=file_name,
                system_name=system or None,
                dept=dept or None,
                purpose=purpose or None,
                retention_raw=retention,
                retention_days=days,
                retention_type=rtype,
                retention_event=event
            )
            
            print(f"[DEBUG] PolicyRow created: id={policy.policy_id}, days={days}, type={rtype}")
            out.append(policy)
    
    return out
