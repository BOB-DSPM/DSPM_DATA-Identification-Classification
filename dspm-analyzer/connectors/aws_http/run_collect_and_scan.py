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

API_TIMEOUT = 120.0


# ============================= 공통 유틸 =============================

def _req_json(url: str, params: Optional[Dict[str, Any]] = None) -> Any:
    r = requests.get(url, params=params, timeout=API_TIMEOUT, headers={"accept": "application/json"})
    r.raise_for_status()
    try:
        return r.json()
    except Exception:
        return r.text


def _probe_endpoint(base: str, use_api_prefix: bool) -> bool:
    """가볍게 s3-buckets로 살아있는지 점검"""
    base = base.rstrip("/")
    path = "/api/s3-buckets" if use_api_prefix else "/s3-buckets"
    url = base + path
    try:
        r = requests.get(url, timeout=API_TIMEOUT, headers={"accept": "application/json"})
        if r.status_code == 200:
            _ = r.json()
            return True
        return False
    except Exception:
        return False


def _resolve_api_base(user_base: str) -> Tuple[str, bool]:
    """
    --api 자동 해석:
      1) user_base + /api
      2) user_base
      3) user_base/explorer + /api
      4) user_base/explorer
    """
    ub = user_base.rstrip("/")
    candidates = [
        (ub, True),
        (ub, False),
        (ub + "/explorer", True),
        (ub + "/explorer", False),
    ]
    for base, use_api in candidates:
        if _probe_endpoint(base, use_api):
            print(f"[info] API base resolved: {base}  (use_api_prefix={use_api})")
            return base, use_api
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


def _safe_key(s: str) -> str:
    """파일명 안전화 (경로 구분자는 유지하고 위험 문자만 제거)"""
    banned = '<>:"\\|?*'
    return "".join(c for c in s if c not in banned)


def _dump_one_payload(dump_dir: Path, service: str, key: str, payload: Any) -> Path:
    """
    dump_dir/<service>/<key(.json)> 로 덤프
    service, key 모두 절대 경로 조합을 존중
    """
    service = _safe_key(service)
    key = _safe_key(key)
    filename = key if key.endswith(".json") else f"{key}.json"
    out_file = dump_dir / service / filename
    out_file.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(payload, str):
        out_file.write_text(payload, encoding="utf-8")
    else:
        out_file.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return out_file


def _display_path(service: str, kind: str, ident: str, leaf: Optional[str] = None, *, ext: Optional[str] = None) -> str:
    """
    절대 경로용 표시 키 생성
    ex) _display_path("dynamodb","explorer","users","item-001", ext=".json")
        -> "dynamodb/explorer/users/item-001.json"
    """
    p = f"{service.strip('/')}/{kind.strip('/')}/{ident.strip('/')}"
    if leaf:
        p += f"/{leaf.strip('/')}"
    if ext:
        p += ext
    return p


def _obj_text_from_common(obj: Dict[str, Any]) -> Optional[str]:
    """explorer 항목에서 본문 텍스트 후보를 공통 규칙으로 추출"""
    if isinstance(obj.get("content"), dict) and isinstance(obj["content"].get("text"), str):
        return obj["content"]["text"]
    if isinstance(obj.get("body"), str):
        return obj["body"]
    if isinstance(obj.get("Text"), str):
        return obj["Text"]
    return None


def _make_blob_for_report(display_key: str, content_text: str, *, source_hint: Optional[str] = None) -> Dict[str, Any]:
    blob = {
        "key": display_key,
        "content": {"text": content_text},
    }
    if source_hint:
        blob["metadata"] = {"source": source_hint}
    return blob


# ============================= 메인 로직 =============================

def collect_and_scan(
    api_base: str,
    out_path: Path,
    services: Optional[List[str]] = None,
    dump_dir: Optional[Path] = None,
) -> Tuple[List[Dict[str, Any]], List[Path]]:
    """
    services: None이면 전체, 일부만 원하면 ["s3","dynamodb"] 처럼 전달
    dump_dir: 원본 payload를 파일로 보관
    """
    base, use_api_prefix = _resolve_api_base(api_base)

    blobs: List[Dict[str, Any]] = []
    saved_files: List[Path] = []

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
        analyze: bool = True,
    ):
        # 1) dump
        if dump_dir is not None:
            path = _dump_one_payload(dump_dir, service, key, payload)
            saved_files.append(path)
            rec = {"service": service, "key": key, "path": str(path)}
            jsonl_fp.write(json.dumps({**rec, "payload": payload}, ensure_ascii=False) + "\n")

        # 2) analyze
        if not analyze:
            return
        text = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False, indent=2)
        disp = display_key if display_key else f"{service}/{key}.json"
        blobs.append(_make_blob_for_report(disp, text, source_hint=source_hint))

    # ---------------- S3 ----------------
    if services is None or "s3" in services:
        arr = _api_get(base, use_api_prefix, "s3-buckets")
        for it in arr or []:
            name = it.get("name")
            if not name:
                continue

            # repository -> 절대 경로로
            repo = _api_get(base, use_api_prefix, f"repositories/s3/{name}")
            repo_disp = _display_path("s3", "repository", name, ext=".json")
            add_blob_record("s3", f"repository/{name}", repo, display_key=repo_disp, source_hint=f"s3/{name}")

            # explorer: 버킷 객체들을 개별 blob
            exp = _api_get(base, use_api_prefix, f"explorer/s3/{name}", params={"max_keys": 200})
            if isinstance(exp, dict):
                if isinstance(exp.get("objects"), list):
                    items = exp["objects"]
                elif isinstance(exp.get("Contents"), list):
                    items = exp["Contents"]
                else:
                    # 전체 덤프만 저장
                    add_blob_record("s3", f"explorer/{name}", exp, source_hint=f"s3/{name}", analyze=False)
                    items = []
            elif isinstance(exp, list):
                items = exp
            else:
                add_blob_record("s3", f"explorer/{name}", exp, source_hint=f"s3/{name}", analyze=False)
                items = []

            for obj in items:
                obj_key = obj.get("key") or obj.get("Key") or obj.get("object_key") or obj.get("name")
                if not obj_key:
                    continue

                # dump 원본 (절대 경로 구조)
                dump_key = f"explorer/{name}/{obj_key}"
                add_blob_record("s3", dump_key, obj, source_hint=f"s3/{name}", analyze=False)

                # 본문 텍스트
                content_text = _obj_text_from_common(obj)
                if content_text is None:
                    content_text = json.dumps(obj, ensure_ascii=False, indent=2)

                # 보고서용 display key는 S3 객체키 그대로(확장자 그대로, .json 미부착)
                disp = _display_path("s3", "explorer", name, obj_key, ext=None)
                blobs.append(_make_blob_for_report(disp, content_text, source_hint=f"s3/{name}"))

    # ---------------- EFS ----------------
    if services is None or "efs" in services:
        arr = _api_get(base, use_api_prefix, "efs-filesystems")
        for it in arr or []:
            fsid = it.get("file_system_id")
            if not fsid:
                continue
            repo = _api_get(base, use_api_prefix, f"repositories/efs/{fsid}")
            disp = _display_path("efs", "repository", fsid, ext=".json")
            add_blob_record("efs", f"repository/{fsid}", repo, display_key=disp, source_hint=f"efs/{fsid}")

    # ---------------- FSx ----------------
    if services is None or "fsx" in services:
        arr = _api_get(base, use_api_prefix, "fsx-filesystems")
        for it in arr or []:
            fsid = it.get("file_system_id")
            if not fsid:
                continue
            repo = _api_get(base, use_api_prefix, f"repositories/fsx/{fsid}")
            disp = _display_path("fsx", "repository", fsid, ext=".json")
            add_blob_record("fsx", f"repository/{fsid}", repo, display_key=disp, source_hint=f"fsx/{fsid}")

    # ---------------- RDS ----------------
    if services is None or "rds" in services:
        arr = _api_get(base, use_api_prefix, "rds-instances")
        for it in arr or []:
            dbid = it.get("db_instance_identifier")
            if not dbid:
                continue
            repo = _api_get(base, use_api_prefix, f"repositories/rds/{dbid}")
            disp = _display_path("rds", "repository", dbid, ext=".json")
            add_blob_record("rds", f"repository/{dbid}", repo, display_key=disp, source_hint=f"rds/{dbid}")

    # ------------- RDS Snapshots -------------
    if services is None or "rds-snapshot" in services or "rds-snapshots" in services:
        arr = _api_get(base, use_api_prefix, "rds-snapshots")
        for it in arr or []:
            sid = it.get("snapshot_id") or it.get("db_snapshot_identifier")
            if not sid:
                continue
            repo = _api_get(base, use_api_prefix, f"repositories/rds-snapshot/{sid}")
            disp = _display_path("rds-snapshot", "repository", sid, ext=".json")
            add_blob_record("rds-snapshot", f"repository/{sid}", repo, display_key=disp, source_hint=f"rds-snapshot/{sid}")

    # ---------------- DynamoDB ----------------
    if services is None or "dynamodb" in services:
        arr = _api_get(base, use_api_prefix, "dynamodb-tables")
        for it in arr or []:
            tname = it.get("table_name")
            if not tname:
                continue

            # repository
            repo = _api_get(base, use_api_prefix, f"repositories/dynamodb/{tname}")
            repo_disp = _display_path("dynamodb", "repository", tname, ext=".json")
            add_blob_record("dynamodb", f"repository/{tname}", repo, display_key=repo_disp, source_hint=f"dynamodb/{tname}")

            # explorer: row 단위로 쪼개 분석
            exp = _api_get(base, use_api_prefix, f"explorer/dynamodb/{tname}", params={"limit": 50})
            items: List[Dict[str, Any]] = []
            if isinstance(exp, dict):
                for k in ("items", "Items", "rows", "Rows", "data", "Data"):
                    if isinstance(exp.get(k), list):
                        items = exp[k]
                        break
                if not items:
                    # 덤프만 남김
                    add_blob_record("dynamodb", f"explorer/{tname}", exp, source_hint=f"dynamodb/{tname}", analyze=False)
            elif isinstance(exp, list):
                items = exp
            else:
                add_blob_record("dynamodb", f"explorer/{tname}", exp, source_hint=f"dynamodb/{tname}", analyze=False)

            for idx, row in enumerate(items):
                # 키/식별자 추출
                leaf = (
                    row.get("id") or row.get("ID") or row.get("pk") or row.get("PK")
                    or row.get("user_id") or row.get("UserId") or str(idx)
                )
                # dump
                dump_key = f"explorer/{tname}/{leaf}"
                add_blob_record("dynamodb", dump_key, row, source_hint=f"dynamodb/{tname}", analyze=False)

                # 보고서 key (절대 경로)
                disp = _display_path("dynamodb", "explorer", tname, leaf, ext=".json")
                content_text = json.dumps(row, ensure_ascii=False, indent=2)
                blobs.append(_make_blob_for_report(disp, content_text, source_hint=f"dynamodb/{tname}"))

    # ---------------- Redshift ----------------
    if services is None or "redshift" in services:
        arr = _api_get(base, use_api_prefix, "redshift-clusters")
        for it in arr or []:
            cid = it.get("cluster_id") or it.get("cluster_identifier")
            if not cid:
                continue
            repo = _api_get(base, use_api_prefix, f"repositories/redshift/{cid}")
            disp = _display_path("redshift", "repository", cid, ext=".json")
            add_blob_record("redshift", f"repository/{cid}", repo, display_key=disp, source_hint=f"redshift/{cid}")

    # ---------------- ElastiCache ----------------
    if services is None or "elasticache" in services:
        arr = _api_get(base, use_api_prefix, "elasticache-clusters")
        for it in arr or []:
            cid = it.get("cluster_id")
            if not cid:
                continue
            repo = _api_get(base, use_api_prefix, f"repositories/elasticache/{cid}")
            disp = _display_path("elasticache", "repository", cid, ext=".json")
            add_blob_record("elasticache", f"repository/{cid}", repo, display_key=disp, source_hint=f"elasticache/{cid}")

    # ---------------- Glacier ----------------
    if services is None or "glacier" in services:
        arr = _api_get(base, use_api_prefix, "glacier-vaults")
        for it in arr or []:
            vname = it.get("vault_name") or it.get("VaultName") or it.get("name")
            if not vname:
                continue
            repo = _api_get(base, use_api_prefix, f"repositories/glacier/{vname}")
            disp = _display_path("glacier", "repository", vname, ext=".json")
            add_blob_record("glacier", f"repository/{vname}", repo, display_key=disp, source_hint=f"glacier/{vname}")

    # ---------------- Backup ----------------
    if services is None or "backup" in services:
        arr = _api_get(base, use_api_prefix, "backup-plans")
        for it in arr or []:
            pid = it.get("plan_id") or it.get("backup_plan_id")
            if not pid:
                continue
            repo = _api_get(base, use_api_prefix, f"repositories/backup/{pid}")
            disp = _display_path("backup", "repository", pid, ext=".json")
            add_blob_record("backup", f"repository/{pid}", repo, display_key=disp, source_hint=f"backup/{pid}")

    # -------- SageMaker Feature Groups --------
    if services is None or "feature-group" in services or "feature-groups" in services:
        m = _api_get(base, use_api_prefix, "feature-groups")
        if isinstance(m, dict):
            for fg_name, meta in m.items():
                repo = _api_get(base, use_api_prefix, f"repositories/feature-group/{fg_name}")
                repo_disp = _display_path("feature-group", "repository", fg_name, ext=".json")
                add_blob_record("feature-group", f"repository/{fg_name}", repo, display_key=repo_disp, source_hint=f"feature-group/{fg_name}")

                exp = _api_get(base, use_api_prefix, f"explorer/feature-group/{fg_name}", params={"max_keys": 20})
                items: List[Dict[str, Any]] = []
                if isinstance(exp, dict):
                    for k in ("items", "rows", "objects", "features"):
                        if isinstance(exp.get(k), list):
                            items = exp[k]
                            break
                    if not items:
                        add_blob_record("feature-group", f"explorer/{fg_name}", exp, source_hint=f"feature-group/{fg_name}", analyze=False)
                elif isinstance(exp, list):
                    items = exp
                else:
                    add_blob_record("feature-group", f"explorer/{fg_name}", exp, source_hint=f"feature-group/{fg_name}", analyze=False)

                for idx, row in enumerate(items):
                    leaf = row.get("feature_name") or row.get("name") or str(idx)
                    dump_key = f"explorer/{fg_name}/{leaf}"
                    add_blob_record("feature-group", dump_key, row, source_hint=f"feature-group/{fg_name}", analyze=False)

                    disp = _display_path("feature-group", "explorer", fg_name, leaf, ext=".json")
                    content_text = json.dumps(row, ensure_ascii=False, indent=2)
                    blobs.append(_make_blob_for_report(disp, content_text, source_hint=f"feature-group/{fg_name}"))

    # ---------------- Glue Databases ----------------
    if services is None or "glue" in services or "glue-databases" in services:
        arr = _api_get(base, use_api_prefix, "glue-databases")
        for it in arr or []:
            name = it.get("name")
            if not name:
                continue
            repo = _api_get(base, use_api_prefix, f"repositories/glue/{name}")
            disp = _display_path("glue", "repository", name, ext=".json")
            add_blob_record("glue", f"repository/{name}", repo, display_key=disp, source_hint=f"glue/{name}")

    # ---------------- Kinesis Streams ----------------
    if services is None or "kinesis" in services or "kinesis-streams" in services:
        arr = _api_get(base, use_api_prefix, "kinesis-streams")
        for it in arr or []:
            sname = it.get("stream_name")
            if not sname:
                continue
            repo = _api_get(base, use_api_prefix, f"repositories/kinesis/{sname}")
            repo_disp = _display_path("kinesis", "repository", sname, ext=".json")
            add_blob_record("kinesis", f"repository/{sname}", repo, display_key=repo_disp, source_hint=f"kinesis/{sname}")

            exp = _api_get(base, use_api_prefix, f"explorer/kinesis/{sname}", params={"limit": 20})
            items: List[Dict[str, Any]] = []
            if isinstance(exp, dict):
                for k in ("records", "Records", "items", "rows"):
                    if isinstance(exp.get(k), list):
                        items = exp[k]
                        break
                if not items:
                    add_blob_record("kinesis", f"explorer/{sname}", exp, source_hint=f"kinesis/{sname}", analyze=False)
            elif isinstance(exp, list):
                items = exp
            else:
                add_blob_record("kinesis", f"explorer/{sname}", exp, source_hint=f"kinesis/{sname}", analyze=False)

            for idx, rec in enumerate(items):
                leaf = rec.get("sequenceNumber") or rec.get("id") or str(idx)
                dump_key = f"explorer/{sname}/{leaf}"
                add_blob_record("kinesis", dump_key, rec, source_hint=f"kinesis/{sname}", analyze=False)

                # 본문
                content_text = _obj_text_from_common(rec)
                if content_text is None:
                    content_text = json.dumps(rec, ensure_ascii=False, indent=2)

                disp = _display_path("kinesis", "explorer", sname, leaf, ext=".json")
                blobs.append(_make_blob_for_report(disp, content_text, source_hint=f"kinesis/{sname}"))

    # ===================== 마무리 저장/분석 =====================
    if jsonl_fp is not None:
        jsonl_fp.close()
        (dump_dir / "index.json").write_text(
            json.dumps({"count": len(saved_files), "files": [str(p) for p in saved_files],
                        "jsonl": str(dump_dir / "collected.jsonl")}, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )

    reports = [analyze_one_blob(b) for b in blobs]
    organize_and_save(reports, out_path)
    return reports, saved_files


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Collect from AWS HTTP Collector and scan with main.py pipeline")
    p.add_argument("--api", required=True, help="Collector base url (e.g., http://211.44.183.248:8000 or .../explorer)")
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
