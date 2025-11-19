# matcher/bucket_match.py
import re
from typing import Dict

# PolicyRow 타입은 기존 코드 그대로 사용한다고 가정
# from .types import PolicyRow (등) 가 있다면 유지

_DEF_SEP = re.compile(r"[-_]+")

def _norm_bucket(s: str) -> str:
    """
    버킷/정책명을 '동일 규칙'으로 정규화:
    - 소문자
    - 앞뒤 공백 제거
    - 역슬래시 → 슬래시
    - s3://, s3/ 접두 제거
    - 첫 세그먼트만 남김 (s3/<bucket>/path → <bucket>)
    - 확장자(.csv/.json/.parquet/.txt) 제거
    - 하이픈/언더스코어 차이 흡수(모두 언더스코어로 통일)
    - 연속된 구분자는 1개로 축약
    """
    if not s:
        return ""
    s = str(s).strip().lower().replace("\\", "/")
    s = re.sub(r"^(s3://|s3/)", "", s)
    s = s.split("/", 1)[0]  # 첫 세그먼트만
    s = re.sub(r"\.(csv|json|parquet|txt)$", "", s, flags=re.I)
    # 'pii-' 접두는 정책/버킷 양쪽에서 있을 수도 있으니 제거 버전도 키로 넣을 예정
    s = s.strip("-_ ")
    # 하이픈/언더스코어 → 언더스코어로 통일
    s = _DEF_SEP.sub("_", s)
    return s

def _variants(name: str):
    """
    비교 관대화용 키 변형 셋:
    - 원본 정규화
    - 'pii_' 접두 추가/제거
    - 하이픈/언더스코어 상호 교환(이미 언더스코어 통일됐으므로 원형=언더스코어 1종)
    """
    n = _norm_bucket(name)
    out = {n}
    # 접두 변형
    if n.startswith("pii_"):
        out.add(n[4:])
    else:
        out.add("pii_" + n)
    return out

def build_policy_slug_index(policies) -> Dict[str, object]:
    """
    정책 리스트 → 매칭용 인덱스(dict). 
    하나의 정책에 대해 여러 '키 변형'을 같은 값으로 맵핑해 둔다.
    """
    idx: Dict[str, object] = {}
    for p in policies:
        # p.file_name (개인정보파일의 명칭) 기준
        keys = _variants(p.file_name)
        for k in keys:
            idx[k] = p
            # 디버그 로그 추가
            print(f"[DEBUG] build_policy_slug_index: '{k}' -> policy_id={p.policy_id}, file_name='{p.file_name}'")
    return idx

def map_bucket_to_policy(bucket: str, slug_index: Dict[str, object]):
    """
    버킷 문자열 → 정책 찾기.
    - _variants로 만든 모든 변형 키를 사용해 탐색
    - 정확 매칭 우선
    - 접두 일치도 허용 (ex: foo_01, foo_prod)
    """
    if not bucket:
        print(f"[DEBUG] map_bucket_to_policy: bucket is empty")
        return None

    # 정확 매칭
    bucket_variants = _variants(bucket)
    print(f"[DEBUG] map_bucket_to_policy: bucket='{bucket}', variants={bucket_variants}")
    
    for k in bucket_variants:
        hit = slug_index.get(k)
        if hit:
            print(f"[DEBUG] map_bucket_to_policy: exact match '{k}' -> policy_id={hit.policy_id}")
            return hit

    # 접두 일치 허용
    b_norms = bucket_variants
    for b in b_norms:
        for k in slug_index.keys():
            if b.startswith(k + "_") or b.startswith(k + "-"):
                hit = slug_index[k]
                print(f"[DEBUG] map_bucket_to_policy: prefix match '{b}' starts with '{k}' -> policy_id={hit.policy_id}")
                return hit

    print(f"[DEBUG] map_bucket_to_policy: no match for bucket '{bucket}'")
    return None
