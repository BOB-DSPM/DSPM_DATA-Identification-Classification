# scripts/aegis_client.py
"""
AEGIS analyzer client (import 버전)
- collector 트리거: trigger_collect(...)
- 결과 목록/트리 가져오기: get_manifest(...), get_tree(...)
- var/results 모든 파일 로드: load_manifest_files(...), load_all(...)
- one-shot: collect_and_load(...)

서버(server.py)는 현재 "/api/collect", "/api/result/manifest", "/api/result/tree" 를 제공한다고 가정.
"""

from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
import json, gzip, requests

# ─────────────────────────────────────────────────────────────
# Collector 호출 (import 방식)
# ─────────────────────────────────────────────────────────────
def trigger_collect(
    server_host: str,
    collector_api: str,
    services: Optional[List[str]] = None,
    only_detected: bool = True,
    extra_args: Optional[List[str]] = None,
    timeout_connect: float = 5.0,
    timeout_read: float = 120.0,
) -> Dict[str, Any]:
    """
    server.py의 /api/collect 엔드포인트를 import 방식으로 호출.
    - server_host: "http://127.0.0.1:9000"
    - collector_api: "http://192.168.0.10:8000" 등
    - services: None or [] or ["all"] 이면 전체
    """
    base = server_host.rstrip("/")
    url = f"{base}/api/collect"
    payload = {
        "collector_api": collector_api,
        "only_detected": bool(only_detected),
        "services": services or [],
        "extra_args": extra_args or [],
    }
    resp = requests.post(url, json=payload, timeout=(timeout_connect, timeout_read))
    resp.raise_for_status()
    return resp.json()  # { ok, returncode, results_front, results_manifest, results_dir }

# ─────────────────────────────────────────────────────────────
# 결과 목록/트리 (서버에서)
# ─────────────────────────────────────────────────────────────
def get_manifest(server_host: str, timeout: float = 10.0) -> Dict[str, Any]:
    """ /api/result/manifest → {"dir": <abs>, "files": [abs...]} """
    url = server_host.rstrip("/") + "/api/result/manifest"
    r = requests.get(url, timeout=timeout); r.raise_for_status()
    return r.json()

def get_tree(server_host: str, timeout: float = 10.0) -> Dict[str, Any]:
    """ /api/result/tree → 디렉토리 트리 JSON """
    url = server_host.rstrip("/") + "/api/result/tree"
    r = requests.get(url, timeout=timeout); r.raise_for_status()
    return r.json()

# ─────────────────────────────────────────────────────────────
# 파일 로더 (로컬 파일 시스템에서 바로 읽기)
# ─────────────────────────────────────────────────────────────
def _is_jsonl(path: Path) -> bool:
    suffs = [s.lower() for s in path.suffixes]
    return (".jsonl" in suffs) or (".ndjson" in suffs)

def _read_text(path: Path) -> str:
    suffs = [s.lower() for s in path.suffixes]
    if ".gz" in suffs:
        with gzip.open(path, "rt", encoding="utf-8") as f:
            return f.read()
    return path.read_text(encoding="utf-8")

def read_any(path: Path) -> Any:
    """
    JSON/JSONL/NDJSON(.gz 포함) → 파싱해서 반환
    그 외 확장자 → 텍스트 그대로 반환
    """
    text = _read_text(path)
    if _is_jsonl(path):
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    if path.suffix.lower() == ".json":
        return json.loads(text)
    return text

def load_manifest_files(
    files: Iterable[str | Path],
    results_dir: Optional[str | Path] = None,
    limit_jsonl: Optional[int] = None,
) -> Dict[str, Any]:
    """
    절대경로 리스트(files)를 순회하며 로드 → {상대경로: 데이터}
    - results_dir: 상대경로 키 계산 기준 디렉토리(보통 /var/results)
    - limit_jsonl: JSONL이 너무 크면 앞 N줄만(미지정=None)
    """
    base = Path(results_dir).resolve() if results_dir else None
    out: Dict[str, Any] = {}
    for f in files:
        p = Path(f).resolve()
        key = str(p.relative_to(base)) if base and base in p.parents else str(p)
        try:
            data = read_any(p)
            if isinstance(data, list) and limit_jsonl is not None:
                data = data[:limit_jsonl]
            out[key] = data
        except Exception as e:
            out[key] = {"_error": str(e)}
    return out

def load_all(results_dir: str | Path, limit_jsonl: Optional[int] = None) -> Dict[str, Any]:
    """
    var/results 밑의 모든 파일을 재귀적으로 읽어 dict로 반환(상대경로 키)
    """
    base = Path(results_dir).resolve()
    files = [str(p) for p in base.rglob("*") if p.is_file()]
    return load_manifest_files(files, results_dir=base, limit_jsonl=limit_jsonl)

# ─────────────────────────────────────────────────────────────
# 편의: 한 번에 수집→전체 로드
# ─────────────────────────────────────────────────────────────
def collect_and_load(
    server_host: str,
    collector_api: str,
    services: Optional[List[str]] = None,
    only_detected: bool = True,
    limit_jsonl: Optional[int] = None,
    timeout_connect: float = 5.0,
    timeout_read: float = 120.0,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    1) /api/collect 호출 → res (manifest 포함)
    2) manifest 기준으로 모든 파일 읽어서 bundle 반환
    - return: (res, bundle)
    """
    res = trigger_collect(
        server_host=server_host,
        collector_api=collector_api,
        services=services,
        only_detected=only_detected,
        timeout_connect=timeout_connect,
        timeout_read=timeout_read,
    )
    results_dir = res.get("results_dir")
    manifest = res.get("results_manifest") or []
    bundle = load_manifest_files(manifest, results_dir=results_dir, limit_jsonl=limit_jsonl)
    return res, bundle
