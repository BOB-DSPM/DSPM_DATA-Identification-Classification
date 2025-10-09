# connectors/aws_http/run_collect_and_scan.py
# --- add project root to sys.path (so we can import main.py) ---
import sys, pathlib
ROOT = pathlib.Path(__file__).resolve().parents[2]  # 프로젝트 루트 추정
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
# ---------------------------------------------------------------

# -*- coding: utf-8 -*-
import json
import requests
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# main.py의 상위 파이프라인 재사용!
from main import analyze_one_blob, organize_and_save

API_TIMEOUT = 12.0


# ----------------------------- HTTP helpers -----------------------------
def _req_json(url: str, params: Optional[Dict[str, Any]] = None) -> Any:
    r = requests.get(url, params=params, timeout=API_TIMEOUT, headers={"accept": "application/json"})
    r.raise_for_status()
    try:
        return r.json()
    except Exception:
        return r.text


def _probe_endpoint(base: str, use_api_prefix: bool) -> bool:
    """
    주어진 base에 대해 실제 라우트가 살아있는지 프로브.
    - 가장 가벼운 엔드포인트인 s3-buckets를 조회해봄.
    """
    base = base.rstrip("/")
    path = "/api/s3-buckets" if use_api_prefix else "/s3-buckets"
    url = base + path
    try:
        r = requests.get(url, timeout=API_TIMEOUT, headers={"accept": "application/json"})
        if r.status_code == 200:
            _ = r.json()  # JSON parse 검증
            return True
        return False
    except Exception:
        return False


def _resolve_api_base(user_base: str) -> Tuple[str, bool]:
    """
    사용자가 준 --api를 바탕으로 실제 동작하는 베이스와 /api 프리픽스 유무를 탐색.
    탐색 순서:
      1) user_base + /api
      2) user_base (no /api)
      3) user_base/explorer + /api
      4) user_base/explorer (no /api)
    """
    candidates = []
    ub = user_base.rstrip("/")
    candidates.append((ub, True))
    candidates.append((ub, False))
    candidates.append((ub + "/explorer", True))
    candidates.append((ub + "/explorer", False))

    for base, use_api in candidates:
        if _probe_endpoint(base, use_api):
            print(f"[info] API base resolved: {base}  (use_api_prefix={use_api})")
            return base, use_api

    # 마지막으로 그냥 사용자 입력 그대로 반환(실패 시 예외는 밑에서 터짐)
    print(f"[warn] Could not auto-resolve API base. Using user provided: {user_base} (assume /api prefix).")
    return ub, True


def _api_get(base: str, use_api_prefix: bool, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
    base = base.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    if use_api_prefix and not path.startswith("/api/"):
        path = "/api" + path
    url = base + path
    return _req_json(url, params=params)
# ------------------------------------------------------------------------


# ----------------------------- I/O helpers ------------------------------
def _safe_key(s: str) -> str:
    """파일명 안전화를 위한 간단한 정규화 (경로 구분자는 그대로 두고 파일명만 정리)"""
    banned = '<>:"\\|?*'
    return "".join(c for c in s if c not in banned)


def _dump_one_payload(dump_dir: Path, service: str, key: str, payload: Any) -> Path:
    service = _safe_key(service)
    key = _safe_key(key)

    # 키가 이미 .json 으로 끝나면 그대로, 아니면 .json 덧붙임
    filename = key if key.endswith(".json") else f"{key}.json"
    out_file = dump_dir / service / filename
    out_file.parent.mkdir(parents=True, exist_ok=True)

    if isinstance(payload, str):
        out_file.write_text(payload, encoding="utf-8")
    else:
        out_file.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return out_file
# ------------------------------------------------------------------------


# --------------------------- blob construction --------------------------
def _make_blob_for_report(
    display_key: str,
    content_text: str,
    *,
    source_hint: Optional[str] = None,
) -> Dict[str, Any]:
    """
    main.analyze_one_blob 이 기대하는 페이로드 형태
    - key: 보고서에 '파일:'로 표기될 경로/이름 (여기서는 실제 객체 키 그대로 사용)
    - content.text: 분석할 본문
    - metadata.source: '소스:' 표기용 힌트 (예: s3/my-bucket)
    """
    blob = {
        "key": display_key,                 # 실제 파일명/키 그대로!
        "content": {"text": content_text},  # 분석 본문
    }
    if source_hint:
        blob["metadata"] = {"source": source_hint}
    return blob
# ------------------------------------------------------------------------


def collect_and_scan(
    api_base: str,
    out_path: Path,
    services: Optional[List[str]] = None,
    dump_dir: Optional[Path] = None,
) -> Tuple[List[Dict[str, Any]], List[Path]]:
    """
    services가 None이면 넓게 커버. 특정 서비스만 돌리고 싶으면 ["s3","efs"]처럼 지정.
    dump_dir가 주어지면 수집된 원본을 파일로 남긴다.
    반환:
      - reports: analyzer 결과 리스트
      - saved_files: dump_dir에 실제로 저장된 원본 파일 경로들
    """
    # --- API base 해석 ---
    base, use_api_prefix = _resolve_api_base(api_base)

    blobs: List[Dict[str, Any]] = []
    saved_files: List[Path] = []

    # JSONL 전체 모음 파일 (선택)
    jsonl_fp = None
    if dump_dir is not None:
        dump_dir.mkdir(parents=True, exist_ok=True)
        jsonl_fp = (dump_dir / "collected.jsonl").open("w", encoding="utf-8")

    def add_blob_record(
        service: str,
        key: str,
        payload: Any,
        *,
        display_key: Optional[str] = None,
        source_hint: Optional[str] = None,
        analyze: bool = True,           # ← 추가
    ):
        # 1) dump
        if dump_dir is not None:
            path = _dump_one_payload(dump_dir, service, key, payload)
            saved_files.append(path)
            record = {
                "service": service,
                "key": key,
                "path": str(path),
                "payload": payload,
            }
            jsonl_fp.write(json.dumps(record, ensure_ascii=False) + "\n")

        # 2) analyze (옵션)
        if not analyze:
            return

        text = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False, indent=2)
        disp = display_key if display_key else f"{service}/{key}.json"
        blobs.append(_make_blob_for_report(disp, text, source_hint=source_hint))

    # -------- S3 --------
    if services is None or "s3" in services:
        arr = _api_get(base, use_api_prefix, "s3-buckets")
        for it in arr or []:
            name = it.get("name")
            if not name:
                continue

            # repository 메타 (그대로 .json로 분석)
            repo = _api_get(base, use_api_prefix, f"repositories/s3/{name}")
            add_blob_record("s3/repository", name, repo, source_hint=f"s3/{name}")

            # explorer: 버킷 안의 객체들을 개별 blob으로!
            exp = _api_get(base, use_api_prefix, f"explorer/s3/{name}", params={"max_keys": 100})
            # 가능한 구조: list, 혹은 {"objects":[...]} 등 다양한 형태를 방어적으로 처리
            if isinstance(exp, dict):
                if "objects" in exp and isinstance(exp["objects"], list):
                    items = exp["objects"]
                elif "Contents" in exp and isinstance(exp["Contents"], list):
                    items = exp["Contents"]
                else:
                    # dict 한 덩어리 그대로 저장/스캔(최악의 경우)
                    add_blob_record("s3/explorer", name, exp, source_hint=f"s3/{name}", analyze=False)
                    items = []
            elif isinstance(exp, list):
                items = exp
            else:
                # 문자열 등 비정형이면 통째로 저장/스캔
                add_blob_record("s3/explorer", name, exp, source_hint=f"s3/{name}", analyze=False)
                items = []

            # 객체 단위로 분해
            for obj in items:
                # 키 후보들
                obj_key = obj.get("key") or obj.get("Key") or obj.get("object_key") or obj.get("name")
                if not obj_key:
                    # 키가 없으면 스킵
                    continue

                # 내용 텍스트 확보
                content_text: Optional[str] = None
                # 1) explorer 응답이 content.text를 포함하는 경우(우선)
                if isinstance(obj.get("content"), dict) and "text" in obj["content"]:
                    content_text = obj["content"]["text"]
                # 2) 일부 구현은 "body"나 "Text" 같은 키를 줄 수도 있음
                elif "body" in obj and isinstance(obj["body"], str):
                    content_text = obj["body"]
                elif "Text" in obj and isinstance(obj["Text"], str):
                    content_text = obj["Text"]

                # dump는 객체 json 그대로 떨궈둠(추적 용이)
                dump_key = f"{name}/{obj_key}"
                add_blob_record("s3/explorer", dump_key, obj, source_hint=f"s3/{name}", analyze=False)

                # 실제 분석은 "파일명 = 객체 키 그대로", "본문 = content_text 있으면 그걸로"
                if content_text is None:
                    # 본문이 없으면 객체 json 자체를 본문으로라도 사용(최소한의 탐지 보장)
                    content_text = json.dumps(obj, ensure_ascii=False, indent=2)

                # blob: display_key는 실제 객체 키 그대로!
                blobs.append(
                    _make_blob_for_report(
                        display_key=f"s3/explorer/{name}/{obj_key}",
                        content_text=content_text,
                        source_hint=f"s3/{name}",
                    )
                )

    # -------- EFS --------
    if services is None or "efs" in services:
        arr = _api_get(base, use_api_prefix, "efs-filesystems")
        for it in arr or []:
            fsid = it.get("file_system_id")
            if not fsid:
                continue
            repo = _api_get(base, use_api_prefix, f"repositories/efs/{fsid}")
            add_blob_record("efs/repository", fsid, repo, source_hint=f"efs/{fsid}")

    # -------- FSx --------
    if services is None or "fsx" in services:
        arr = _api_get(base, use_api_prefix, "fsx-filesystems")
        for it in arr or []:
            fsid = it.get("file_system_id")
            if not fsid:
                continue
            repo = _api_get(base, use_api_prefix, f"repositories/fsx/{fsid}")
            add_blob_record("fsx/repository", fsid, repo, source_hint=f"fsx/{fsid}")

    # -------- RDS --------
    if services is None or "rds" in services:
        arr = _api_get(base, use_api_prefix, "rds-instances")
        for it in arr or []:
            dbid = it.get("db_instance_identifier")
            if not dbid:
                continue
            repo = _api_get(base, use_api_prefix, f"repositories/rds/{dbid}")
            add_blob_record("rds/repository", dbid, repo, source_hint=f"rds/{dbid}")

    # -------- RDS Snapshots --------
    if services is None or "rds-snapshot" in services or "rds-snapshots" in services:
        arr = _api_get(base, use_api_prefix, "rds-snapshots")
        for it in arr or []:
            sid = it.get("snapshot_id") or it.get("db_snapshot_identifier")
            if not sid:
                continue
            repo = _api_get(base, use_api_prefix, f"repositories/rds-snapshot/{sid}")
            add_blob_record("rds-snapshot/repository", sid, repo, source_hint=f"rds-snapshot/{sid}")

    # -------- DynamoDB --------
    if services is None or "dynamodb" in services:
        arr = _api_get(base, use_api_prefix, "dynamodb-tables")
        for it in arr or []:
            tname = it.get("table_name")
            if not tname:
                continue
            repo = _api_get(base, use_api_prefix, f"repositories/dynamodb/{tname}")
            add_blob_record("dynamodb/repository", tname, repo, source_hint=f"dynamodb/{tname}")

            exp = _api_get(base, use_api_prefix, f"explorer/dynamodb/{tname}", params={"limit": 50})
            add_blob_record("dynamodb/explorer", tname, exp, source_hint=f"dynamodb/{tname}")

    # -------- Redshift --------
    if services is None or "redshift" in services:
        arr = _api_get(base, use_api_prefix, "redshift-clusters")
        for it in arr or []:
            cid = it.get("cluster_id") or it.get("cluster_identifier")
            if not cid:
                continue
            repo = _api_get(base, use_api_prefix, f"repositories/redshift/{cid}")
            add_blob_record("redshift/repository", cid, repo, source_hint=f"redshift/{cid}")

    # -------- ElastiCache --------
    if services is None or "elasticache" in services:
        arr = _api_get(base, use_api_prefix, "elasticache-clusters")
        for it in arr or []:
            cid = it.get("cluster_id")
            if not cid:
                continue
            repo = _api_get(base, use_api_prefix, f"repositories/elasticache/{cid}")
            add_blob_record("elasticache/repository", cid, repo, source_hint=f"elasticache/{cid}")

    # -------- Glacier --------
    if services is None or "glacier" in services:
        arr = _api_get(base, use_api_prefix, "glacier-vaults")
        for it in arr or []:
            vname = it.get("vault_name") or it.get("VaultName") or it.get("name")
            if not vname:
                continue
            repo = _api_get(base, use_api_prefix, f"repositories/glacier/{vname}")
            add_blob_record("glacier/repository", vname, repo, source_hint=f"glacier/{vname}")

    # -------- Backup --------
    if services is None or "backup" in services:
        arr = _api_get(base, use_api_prefix, "backup-plans")
        for it in arr or []:
            pid = it.get("plan_id") or it.get("backup_plan_id")
            if not pid:
                continue
            repo = _api_get(base, use_api_prefix, f"repositories/backup/{pid}")
            add_blob_record("backup/repository", pid, repo, source_hint=f"backup/{pid}")

    # -------- SageMaker Feature Groups --------
    if services is None or "feature-group" in services or "feature-groups" in services:
        m = _api_get(base, use_api_prefix, "feature-groups")
        if isinstance(m, dict):
            for fg_name, meta in m.items():
                repo = _api_get(base, use_api_prefix, f"repositories/feature-group/{fg_name}")
                add_blob_record("feature-group/repository", fg_name, repo, source_hint=f"feature-group/{fg_name}")
                exp = _api_get(base, use_api_prefix, f"explorer/feature-group/{fg_name}", params={"max_keys": 20})
                add_blob_record("feature-group/explorer", fg_name, exp, source_hint=f"feature-group/{fg_name}")

    # -------- Glue Databases --------
    if services is None or "glue" in services or "glue-databases" in services:
        arr = _api_get(base, use_api_prefix, "glue-databases")
        for it in arr or []:
            name = it.get("name")
            if not name:
                continue
            repo = _api_get(base, use_api_prefix, f"repositories/glue/{name}")
            add_blob_record("glue/repository", name, repo, source_hint=f"glue/{name}")

    # -------- Kinesis Streams --------
    if services is None or "kinesis" in services or "kinesis-streams" in services:
        arr = _api_get(base, use_api_prefix, "kinesis-streams")
        for it in arr or []:
            sname = it.get("stream_name")
            if not sname:
                continue
            repo = _api_get(base, use_api_prefix, f"repositories/kinesis/{sname}")
            add_blob_record("kinesis/repository", sname, repo, source_hint=f"kinesis/{sname}")
            exp = _api_get(base, use_api_prefix, f"explorer/kinesis/{sname}", params={"limit": 20})
            add_blob_record("kinesis/explorer", sname, exp, source_hint=f"kinesis/{sname}")

    # JSONL 핸들 닫기 + index.json 작성
    if jsonl_fp is not None:
        jsonl_fp.close()
        index = {
            "count": len(saved_files),
            "files": [str(p) for p in saved_files],
            "jsonl": str(dump_dir / "collected.jsonl"),
        }
        (dump_dir / "index.json").write_text(json.dumps(index, ensure_ascii=False, indent=2), encoding="utf-8")

    # === 수집된 blobs를 main.py 파이프라인에 전달 ===
    reports = [analyze_one_blob(b) for b in blobs]
    organize_and_save(reports, out_path)
    return reports, saved_files


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Collect from AWS HTTP Collector and scan with main.py pipeline")
    p.add_argument("--api", required=True, help="Collector base url (e.g., http://192.168.0.10:8000 or .../explorer)")
    p.add_argument("--services", default="", help="Comma-separated services (e.g., s3,dynamodb). Empty=all")
    p.add_argument("--out", default="results_all.json", help="Output result json")
    p.add_argument("--dump-dir", default="", help="(optional) Directory to dump raw collected payloads")
    args = p.parse_args()

    svcs = [s.strip() for s in args.services.split(",") if s.strip()] or None
    dump_dir = Path(args.dump_dir) if args.dump_dir else None

    collect_and_scan(args.api, Path(args.out), services=svcs, dump_dir=dump_dir)
    print(f"[done] Saved analysis: {Path(args.out).resolve()}")
    if dump_dir:
        print(f"[done] Dumped raw payloads under: {dump_dir.resolve()}")
