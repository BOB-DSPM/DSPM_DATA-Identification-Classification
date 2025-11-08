# server.py
# FastAPI for AEGIS Analyzer (front-only).
# - 표준 결과 경로: ./var/results/
# - 파일 단위(front-list/...) + 리소스(source) 단위(source-summary/...) 동시 지원
# - collector 트리거는 var/results/results_all.json 으로 고정, 그 옆에 results_front.json 생성됨
# - 기본=전체 리소스: services 미지정([]) 또는 ["all"] / ["*"] 이면 --services 전달 안함

import os, io, csv, json, hashlib, subprocess, sys, tarfile, tempfile, shutil
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Literal, Tuple
DSPM_ANALYZER_DIR = Path(__file__).resolve().parent / "dspm-analyzer"
if str(DSPM_ANALYZER_DIR) not in sys.path:
    sys.path.insert(0, str(DSPM_ANALYZER_DIR))
from fastapi import FastAPI, Query, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
# ─────────────────────────────────────────────────────────────
# 표준 경로 고정: var/results/*
# ─────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent
RESULTS_DIR = ROOT / "var" / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

RESULTS_FRONT_JSON = RESULTS_DIR / "results_front.json"
RESULTS_ALL_JSON   = RESULTS_DIR / "results_all.json"
RESULTS_SOURCE_SUM = RESULTS_DIR / "results_front_by_source.json"  # organize_and_save()가 생성

CONNECTOR_SCRIPT = Path(os.getenv(
    "CONNECTOR_SCRIPT",
    str(ROOT / "dspm-analyzer" / "connectors" / "aws_http" / "run_collect_and_scan.py"),
)).resolve()

# ─────────────────────────────────────────────────────────────
# App
# ─────────────────────────────────────────────────────────────
app = FastAPI(title="AEGIS Analyzer API (front-only)", version="3.2.1")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)

def _sha12(s: str) -> str:
    return hashlib.sha1((s or "").encode("utf-8")).hexdigest()[:12]

# 안전 JSON 로더 (비어있거나 손상되어도 None 반환)
def _safe_read_json(path: Path) -> Optional[Any]:
    try:
        if not path.exists():
            return None
        if path.stat().st_size == 0:
            return None
        txt = path.read_text(encoding="utf-8")
        if not txt.strip():
            return None
        return json.loads(txt)
    except Exception:
        return None

# ─────────────────────────────────────────────────────────────
# Manifest / Tree helpers
# ─────────────────────────────────────────────────────────────
def _manifest_recursive(base: Path) -> List[str]:
    """var/results 폴더의 모든 파일 절대경로 목록을 정렬하여 반환."""
    try:
        return sorted(str(p.resolve()) for p in base.rglob("*") if p.is_file())
    except Exception:
        return []

def _tree_node(p: Path) -> Dict[str, Any]:
    try:
        if p.is_dir():
            return {
                "type": "dir",
                "name": p.name,
                "children": [
                    _tree_node(c) for c in sorted(p.iterdir(), key=lambda x: (x.is_file(), x.name.lower()))
                ],
            }
        return {"type": "file", "name": p.name, "size": p.stat().st_size, "path": str(p.resolve())}
    except Exception as e:
        return {"type": "error", "name": p.name, "error": str(e)}

# ─────────────────────────────────────────────────────────────
# Models
# ─────────────────────────────────────────────────────────────
class FrontEntityItem(BaseModel):
    count: int
    bucket: str
    values: List[str] = Field(default_factory=list)
    saved_path: Optional[str] = None
class RDSAnonymizationScanRequest(BaseModel):
    host: str = Field(..., description="RDS 호스트 주소")
    port: int = Field(3306, description="RDS 포트")
    user: str = Field(..., description="RDS 사용자명")
    password: str = Field(..., description="RDS 비밀번호")
    database: str = Field(..., description="데이터베이스명")
    tables: Optional[List[str]] = Field(None, description="스캔할 테이블 리스트 (None=전체)")
    collector_api: Optional[str] = Field(None, description="추가 데이터 수집 API (선택)")

class RDSAnonymizationScanResponse(BaseModel):
    ok: bool
    scan_result: Optional[Dict[str, Any]] = None
    collector_result: Optional[Dict[str, Any]] = None
    combined_report: Optional[str] = None
    error: Optional[str] = None

class FrontStatsModel(BaseModel):
    rows_scanned: Optional[int] = None
    total_entities: Optional[int] = None
    unique_entity_types: List[str] = Field(default_factory=list)

class FrontItem(BaseModel):
    id: str
    file: str
    source: Optional[str] = None      # ex) "s3/my-mlops-dev-data"
    type: Optional[str] = None        # ex) "text/plain"
    category: Optional[str] = None    # "identifiers"|"sensitive"|"public"|"none"
    reason: Optional[str] = None
    risk_hints: Dict[str, Any] = Field(default_factory=dict)
    stats: FrontStatsModel = Field(default_factory=FrontStatsModel)
    entities: Dict[str, FrontEntityItem] = Field(default_factory=dict)
    ai_hits: List[Dict[str, Any]] = Field(default_factory=list)  # 이 줄 추가
class ListResponse(BaseModel):
    total: int
    page: int
    size: int
    items: List[FrontItem]

class CategoryCountsResponse(BaseModel):
    total: int
    categories: Dict[str, int]

# 기본=전체 리소스 → services 기본값을 [] 로
class _CollectBody(BaseModel):
    collector_api: str
    services: List[str] = Field(default_factory=list)  # [] or ["all"] → 전체
    only_detected: bool = False
    extra_args: List[str] = Field(default_factory=list)

class CollectResponse(BaseModel):
    ok: bool
    returncode: int
    results_front: str
    results_manifest: List[str]
    results_dir: str
    cmd: List[str]
    stdout: str
    stderr: str
    error: Optional[str] = None

class RDSCollectorScanRequest(BaseModel):
    collector_api: str = Field(..., description="Collector API 주소")
    rds_configs: Dict[str, Dict[str, Any]] = Field(
        ..., 
        description="RDS 연결 설정 {db_identifier: {port, db_name, user, password}}"
    )
    target_tables: Optional[Dict[str, List[str]]] = Field(
        None,
        description="스캔할 테이블 {db_identifier: [table_names]} (None=전체)"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "collector_api": "http://211.44.183.248:8000",
                "rds_configs": {
                    "my-rds-instance": {
                        "port": 5432,
                        "db_name": "postgres",
                        "user": "postgres",
                        "password": "password"
                    }
                },
                "target_tables": {
                    "my-rds-instance": ["users", "orders"]
                }
            }
        }

# v2: 간소화된 RDS 스캔 요청 (자동 메타데이터 활용 + 전체 자동 스캔)
class RDSCollectorScanRequestV2(BaseModel):
    collector_api: str = Field(..., description="Collector API 주소")
    passwords: Optional[Dict[str, str]] = Field(
        None,
        description="각 RDS별 비밀번호 {db_identifier: password} (없으면 기본값 사용)"
    )
    target_tables: Optional[Dict[str, List[str]]] = Field(
        None,
        description="스캔할 테이블 {db_identifier: [table_names]} (None=전체)"
    )
    default_user: str = Field("madeit", description="기본 사용자명")
    default_password: str = Field("madeit1022!", description="기본 비밀번호")
    
    class Config:
        json_schema_extra = {
            "example": {
                "collector_api": "http://211.44.183.248:8000",
                "passwords": {
                    "my-rds-1": "custom_password1"
                },
                "default_user": "madeit",
                "default_password": "madeit1022!"
            }
        }

class RDSCollectorScanResponse(BaseModel):
    ok: bool
    result: Optional[Dict[str, Any]] = None
    report_path: Optional[str] = None
    error: Optional[str] = None

# ─────────────────────────────────────────────────────────────
# Store (front-only)
# ─────────────────────────────────────────────────────────────
class FrontStore:
    def __init__(self, path: Path):
        self.path = path
        self.mtime = 0.0
        self.items: List[FrontItem] = []

    def summarize_by_source_runtime(self) -> List[Dict[str, Any]]:
        """results_front.json 로드된 self.items 기반 source 별 엔티티 집계(런타임)."""
        self.ensure()
        acc: Dict[str, Dict[str, int]] = {}
        counts_by_category: Dict[str, Dict[str, int]] = {}

        for it in self.items:
            src = it.source or ""
            if src not in acc:
                acc[src] = {}
                counts_by_category[src] = {"public": 0, "sensitive": 0, "identifiers": 0, "none": 0}

            for ent, info in (it.entities or {}).items():
                acc[src][ent] = acc[src].get(ent, 0) + int(info.count or 0)

            cat = (it.category or "none").lower()
            if cat not in counts_by_category[src]:
                counts_by_category[src][cat] = 0
            counts_by_category[src][cat] += 1

        out: List[Dict[str, Any]] = []
        for src, ents in acc.items():
            total_entities = sum(ents.values())
            top_entities = sorted(ents.items(), key=lambda x: x[1], reverse=True)[:5]
            row = {
                "source": src,
                "total_objects": sum(counts_by_category[src].values()),
                "category_distribution": counts_by_category[src],
                "total_entities": total_entities,
                "top_entities": top_entities,
                "all_entities": sorted(ents.items(), key=lambda x: x[1], reverse=True),
            }
            out.append(row)
        out.sort(key=lambda r: r["source"])
        return out

    def _normalize(self, raw: Dict[str, Any]) -> FrontItem:
        file = raw.get("file") or raw.get("path") or ""
        src = raw.get("source")
        typ = raw.get("type")
        cat = raw.get("category")
        reason = raw.get("reason")
        hints = raw.get("risk_hints") or {}
        st = raw.get("stats") or {}
        ents = raw.get("entities") or {}
        ai_hits = raw.get("ai_hits", [])
        rid = _sha12(f"{file}|{src}|{typ}|{cat}")

        n_ents: Dict[str, FrontEntityItem] = {}
        for k, v in ents.items():
            if isinstance(v, dict):
                n_ents[k] = FrontEntityItem(
                    count=int(v.get("count", 0)),
                    bucket=str(v.get("bucket", "public")),
                    values=list(v.get("values") or []),
                    saved_path=v.get("saved_path"),
                )

        return FrontItem(
            id=rid, file=file, source=src, type=typ, category=cat, reason=reason,
            risk_hints=hints,
            stats=FrontStatsModel(
                rows_scanned=st.get("rows_scanned"),
                total_entities=st.get("total_entities"),
                unique_entity_types=list(st.get("unique_entity_types") or []),
            ),
            entities=n_ents,
            ai_hits=ai_hits, 
        )

    def _load(self):
        """파일이 없거나 비어있거나 손상이어도 예외 없이 빈 결과로."""
        try:
            if not self.path.exists() or self.path.stat().st_size == 0:
                self.items = []
                self.mtime = self.path.stat().st_mtime if self.path.exists() else 0.0
                return
            mt = self.path.stat().st_mtime
            if mt == self.mtime:
                return
            data = _safe_read_json(self.path)
            raws = data if isinstance(data, list) else (data.get("items", []) if isinstance(data, dict) else [])
            self.items = [self._normalize(r) for r in raws if isinstance(r, dict)]
            self.mtime = mt
        except Exception:
            # 어떤 이유든 로드 실패 시 안전 디폴트
            self.items = []
            try:
                self.mtime = self.path.stat().st_mtime
            except Exception:
                self.mtime = 0.0

    def ensure(self): 
        self._load()

    def stats(self, *, include_top: bool = True, include_type: bool = True) -> Dict[str, Any]:
        self.ensure()
        total = len(self.items)
        detected_objs = 0
        cat_dist: Dict[str, int] = {}
        type_dist: Dict[str, int] = {}
        ent_counts: Dict[str, int] = {}

        for it in self.items:
            if it.entities:
                detected_objs += 1
            cat = (it.category or "none").lower()
            cat_dist[cat] = cat_dist.get(cat, 0) + 1

            if include_type:
                typ = (it.type or "unknown").lower()
                type_dist[typ] = type_dist.get(typ, 0) + 1

            for k, v in it.entities.items():
                ent_counts[k] = ent_counts.get(k, 0) + int(v.count or 0)

        rate = round((detected_objs / total) * 100, 2) if total else 0.0
        sorted_entities = sorted(ent_counts.items(), key=lambda x: x[1], reverse=True)

        out = {
            "total_objects": total,
            "detected_objects": detected_objs,
            "detection_rate": rate,
            "category_distribution": cat_dist,
        }
        if include_type:
            out["type_distribution"] = type_dist
        if include_top:
            out["top_entities"] = sorted_entities[:5]
        out["all_entities"] = sorted_entities
        return out

    def category_counts(self) -> CategoryCountsResponse:
        self.ensure()
        d: Dict[str, int] = {}
        for it in self.items:
            k = (it.category or "none").lower()
            d[k] = d.get(k, 0) + 1
        return CategoryCountsResponse(total=len(self.items), categories=d)

    def query(
        self,
        q: Optional[str] = None,
        category: Optional[str] = None,
        type_: Optional[str] = None,
        entity: Optional[str] = None,
        has_entities: Optional[Literal["yes","no","any"]] = "any",
        source: Optional[str] = None,
        source_prefix: Optional[str] = None,
        file_prefix: Optional[str] = None,
    ) -> List[FrontItem]:
        self.ensure()
        out: List[FrontItem] = []
        for it in self.items:
            if category and (it.category or "").lower() != category.lower(): continue
            if type_ and (it.type or "").lower() != type_.lower(): continue
            if entity and entity not in it.entities: continue
            if has_entities == "yes" and not it.entities: continue
            if has_entities == "no" and it.entities: continue
            if source and (it.source or "") != source: continue
            if source_prefix and not (it.source or "").startswith(source_prefix): continue
            if file_prefix and not (it.file or "").startswith(file_prefix): continue
            if q:
                hay = " ".join([it.file or "", it.source or "", it.reason or "",
                                json.dumps(list(it.entities.keys()), ensure_ascii=False)])
                if q.lower() not in hay.lower(): continue
            out.append(it)
        return out

front_store = FrontStore(RESULTS_FRONT_JSON)

# ─────────────────────────────────────────────────────────────
# Health
# ─────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"ok": True}

# ─────────────────────────────────────────────────────────────
# Endpoints — 파일 단위
# ─────────────────────────────────────────────────────────────
@app.get("/api/result/front-stats")
def front_stats(include_top: Optional[str] = None, include_type: Optional[str] = None):
    def as_bool(x: Optional[str]) -> bool:
        return str(x).lower() in ("1", "true", "yes", "y")
    return front_store.stats(include_top=as_bool(include_top), include_type=as_bool(include_type))

@app.get("/api/result/category-counts", response_model=CategoryCountsResponse)
def category_counts():
    return front_store.category_counts()

# (호환용) 과거 이름 유지
@app.get("/api/result/categories", response_model=CategoryCountsResponse)
def categories_alias():
    return front_store.category_counts()

@app.get("/api/result/front-list", response_model=ListResponse)
def front_list(
    page: int = Query(1, ge=1), size: int = Query(20, ge=1, le=200),
    q: Optional[str] = None,
    category: Optional[str] = None,
    type: Optional[str] = Query(None, alias="type"),
    entity: Optional[str] = None,
    has_entities: Optional[Literal["yes","no","any"]] = Query("any"),
    source: Optional[str] = None,
    source_prefix: Optional[str] = None,
    file_prefix: Optional[str] = None,
):
    rows = front_store.query(q=q, category=category, type_=type, entity=entity, has_entities=has_entities,
                             source=source, source_prefix=source_prefix, file_prefix=file_prefix)
    total=len(rows); start=(page-1)*size; end=start+size
    return ListResponse(total=total, page=page, size=size, items=rows[start:end])

@app.get("/api/result/front-category/{category}", response_model=ListResponse)
def front_category(
    category: Literal["public","sensitive","identifiers","none"],
    page: int = Query(1, ge=1), size: int = Query(20, ge=1, le=200),
    q: Optional[str] = None,
    type: Optional[str] = Query(None, alias="type"),
    entity: Optional[str] = None,
    has_entities: Optional[Literal["yes","no","any"]] = Query("any"),
    source: Optional[str] = None,
    source_prefix: Optional[str] = None,
    file_prefix: Optional[str] = None,
):
    rows = front_store.query(q=q, category=category, type_=type, entity=entity, has_entities=has_entities,
                             source=source, source_prefix=source_prefix, file_prefix=file_prefix)
    total=len(rows); start=(page-1)*size; end=start+size
    return ListResponse(total=total, page=page, size=size, items=rows[start:end])

@app.get("/api/result/front-source/{source:path}", response_model=ListResponse)
def front_source(
    source: str,
    page: int = Query(1, ge=1), size: int = Query(20, ge=1, le=200),
    q: Optional[str] = None,
    category: Optional[str] = None,
    type: Optional[str] = Query(None, alias="type"),
    entity: Optional[str] = None,
    has_entities: Optional[Literal["yes","no","any"]] = Query("any"),
    file_prefix: Optional[str] = None,
):
    rows = front_store.query(q=q, category=category, type_=type, entity=entity,
                             has_entities=has_entities, source=source, file_prefix=file_prefix)
    total=len(rows); start=(page-1)*size; end=start+size
    return ListResponse(total=total, page=page, size=size, items=rows[start:end])

@app.get("/api/result/front/{rid}", response_model=FrontItem)
def front_get(rid: str):
    front_store.ensure()
    for it in front_store.items:
        if it.id == rid: 
            return it
    # 404 대신 빈 형태를 주고 싶다면 아래 반환으로 바꿔도 됨
    raise Exception("Front result not found")

# ─────────────────────────────────────────────────────────────
# Endpoints — 리소스(source) 단위 요약 (organize_and_save가 만들어 주는 인덱스 사용)
# ─────────────────────────────────────────────────────────────
@app.get("/api/result/source-summary")
def source_summary():
    data = _safe_read_json(RESULTS_SOURCE_SUM)
    if isinstance(data, list):
        return {"items": data}
    # fallback (파일이 없거나 손상일 경우 런타임 집계)
    return {"items": front_store.summarize_by_source_runtime()}

# ─────────────────────────────────────────────────────────────
# Manifest / Tree / Archive endpoints 
# ─────────────────────────────────────────────────────────────
@app.get("/api/result/manifest")
def result_manifest():
    return {
        "dir": str(RESULTS_DIR.resolve()),
        "files": _manifest_recursive(RESULTS_DIR),
    }

@app.get("/api/result/tree")
def result_tree():
    return _tree_node(RESULTS_DIR)

@app.get("/api/result/archive")
def result_archive(fmt: Literal["zip","tar.gz"]="zip"):
    base = RESULTS_DIR
    if fmt == "zip":
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".zip"); tmp.close()
        shutil.make_archive(tmp.name[:-4], "zip", root_dir=base.parent, base_dir=base.name)
        return FileResponse(tmp.name, media_type="application/zip", filename="results.zip")
    else:
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".tar.gz"); tmp.close()
        with tarfile.open(tmp.name, "w:gz") as tar:
            tar.add(str(base), arcname=base.name)
        return FileResponse(tmp.name, media_type="application/gzip", filename="results.tar.gz")

# ─────────────────────────────────────────────────────────────
# Collector trigger — 결과 폴더 고정(var/results)
# 실패 시에도 200 + ok:false 로 응답 (프론트 일관성)
# ─────────────────────────────────────────────────────────────
@app.post("/api/collect", response_model=CollectResponse)
def trigger_collect(req: _CollectBody = Body(...)):
    # collector_api 최소 유효성 (에러도 ok:false 로 반환)
    if not (req.collector_api and req.collector_api.startswith(("http://","https://"))):
        return CollectResponse(
            ok=False, returncode=400, cmd=[],
            results_front=str(RESULTS_FRONT_JSON.resolve()),
            results_manifest=_manifest_recursive(RESULTS_DIR),
            results_dir=str(RESULTS_DIR.resolve()),
            stdout="", stderr="", error="collector_api must start with http:// or https://"
        )

    if not CONNECTOR_SCRIPT.exists():
        return CollectResponse(
            ok=False, returncode=127, cmd=[],
            results_front=str(RESULTS_FRONT_JSON.resolve()),
            results_manifest=_manifest_recursive(RESULTS_DIR),
            results_dir=str(RESULTS_DIR.resolve()),
            stdout="", stderr="", error=f"Connector script not found: {CONNECTOR_SCRIPT}"
        )

    out_path = RESULTS_ALL_JSON
    env = os.environ.copy()
    if req.only_detected:
        env["ONLY_DETECTED"] = "1"

    cmd = [sys.executable, str(CONNECTOR_SCRIPT), "--api", req.collector_api, "--out", str(out_path)]

    sv = [s.lower() for s in (req.services or [])]
    is_all = (not sv) or (sv == ["all"]) or (sv == ["*"])
    if not is_all:
        cmd += ["--services", ",".join(req.services)]

    if req.extra_args:
        cmd += req.extra_args

    try:
        proc = subprocess.run(
            cmd, cwd=str(ROOT), env=env, text=True,
            stdout=None, stderr=None  # ← None으로 변경하면 터미널에 직접 출력
        )
        # organize_and_save()가 만든 front 보정
        legacy_front = ROOT / "dspm-analyzer" / "results_front.json"
        if not RESULTS_FRONT_JSON.exists() and legacy_front.exists():
            RESULTS_FRONT_JSON.write_text(legacy_front.read_text(encoding="utf-8"), encoding="utf-8")

        # 리로드
        front_store.mtime = 0.0
        front_store.ensure()

        manifest = _manifest_recursive(RESULTS_DIR)
        ok = (proc.returncode == 0) and RESULTS_FRONT_JSON.exists()

        return CollectResponse(
            ok=ok,
            returncode=proc.returncode,
            cmd=cmd,
            results_front=str(RESULTS_FRONT_JSON.resolve()),
            results_manifest=manifest,
            results_dir=str(RESULTS_DIR.resolve()),
            stdout=(proc.stdout or "")[-4000:],
            stderr=(proc.stderr or "")[-4000:],
            error=None if ok else "collector run failed or results_front.json missing"
        )
    except Exception as e:
        # 서브프로세스 자체가 터진 경우
        return CollectResponse(
            ok=False, returncode=500, cmd=cmd,
            results_front=str(RESULTS_FRONT_JSON.resolve()),
            results_manifest=_manifest_recursive(RESULTS_DIR),
            results_dir=str(RESULTS_DIR.resolve()),
            stdout="", stderr="", error=str(e)
        )

# 수동 리로드(디버그용)
@app.post("/api/result/reload")
def reload_front():
    front_store.mtime = 0.0
    front_store.ensure()
    return {"ok": True, "count": len(front_store.items), "path": str(RESULTS_FRONT_JSON)}

@app.get("/api/result/source/entities")
def source_entities_qs(source: str):
    data = _safe_read_json(RESULTS_SOURCE_SUM)
    if isinstance(data, list):
        for row in data:
            if row.get("source") == source:
                return row
    # 파일이 없어도 런타임으로 제공
    for row in front_store.summarize_by_source_runtime():
        if row.get("source") == source:
            return row
    return {"error": "source not found"}

@app.post("/api/scan/rds-anonymization", response_model=RDSAnonymizationScanResponse)
def scan_rds_anonymization_endpoint(req: RDSAnonymizationScanRequest = Body(...)):
    """
    RDS 익명화 검증 스캔 실행
    
    1. RDS에서 익명화된 레코드 탐지
    2. 원본 ID 추출 및 잔존 데이터 검증
    3. (선택) Collector API 연동하여 추가 데이터 수집
    4. 통합 리포트 생성
    """
    try:
        # 1단계: RDS 익명화 스캔
        print(f"\n[API] RDS 익명화 스캔 시작: {req.host}:{req.port}/{req.database}")
        
        from rds_anonymization_scanner import scan_rds_anonymization
        
        rds_config = {
            'host': req.host,
            'port': req.port,
            'user': req.user,
            'password': req.password,
            'database': req.database,
        }
        
        scan_result = scan_rds_anonymization(rds_config, req.tables)
        
        if 'error' in scan_result:
            return RDSAnonymizationScanResponse(
                ok=False,
                error=scan_result['error']
            )
        
        # 2단계: (선택) Collector API 연동
        collector_result = None
        if req.collector_api:
            print(f"\n[API] Collector 연동: {req.collector_api}")
            try:
                # 기존 collect 로직 재사용
                from aegis_client import trigger_collect
                
                collector_result = trigger_collect(
                    server_host="http://127.0.0.1:9000",  # 자기 자신
                    collector_api=req.collector_api,
                    services=None,  # 전체 리소스
                    only_detected=True
                )
            except Exception as e:
                print(f"[API] Collector 연동 실패: {e}")
                collector_result = {'error': str(e)}
        
        # 3단계: 통합 리포트 생성
        combined_report_path = RESULTS_DIR / "rds_anonymization_report.json"
        combined_report = {
            'scan_time': scan_result.get('scan_time'),
            'rds_scan': scan_result,
            'collector_scan': collector_result,
            'summary': {
                'rds_status': scan_result['summary']['status'],
                'anonymized_records': scan_result['summary']['total_anonymized'],
                'residual_data_found': scan_result['summary']['residual_data_found'],
                'collector_status': 'ok' if collector_result and collector_result.get('ok') else 'skipped'
            }
        }
        
        combined_report_path.write_text(
            json.dumps(combined_report, ensure_ascii=False, indent=2),
            encoding='utf-8'
        )
        
        print(f"\n[API] 통합 리포트 저장: {combined_report_path.resolve()}")
        
        return RDSAnonymizationScanResponse(
            ok=True,
            scan_result=scan_result,
            collector_result=collector_result,
            combined_report=str(combined_report_path.resolve())
        )
    
    except Exception as e:
        import traceback
        error_msg = f"{str(e)}\n\n{traceback.format_exc()}"
        print(f"[API] RDS 익명화 스캔 실패:\n{error_msg}")
        
        return RDSAnonymizationScanResponse(
            ok=False,
            error=error_msg
        )


@app.get("/api/scan/rds-anonymization/report")
def get_rds_anonymization_report():
    """RDS 익명화 검증 리포트 조회"""
    report_path = RESULTS_DIR / "rds_anonymization_report.json"
    
    if not report_path.exists():
        return {"error": "리포트가 존재하지 않습니다. 먼저 스캔을 실행하세요."}
    
    try:
        data = json.loads(report_path.read_text(encoding='utf-8'))
        return data
    except Exception as e:
        return {"error": f"리포트 읽기 실패: {e}"}


@app.get("/api/scan/rds-anonymization/violations")
def get_rds_anonymization_violations():
    """RDS 익명화 위반 사항만 조회"""
    report_path = RESULTS_DIR / "rds_anonymization_report.json"
    
    if not report_path.exists():
        return {"error": "리포트가 존재하지 않습니다."}
    
    try:
        data = json.loads(report_path.read_text(encoding='utf-8'))
        rds_scan = data.get('rds_scan', {})
        verification = rds_scan.get('verification', {})
        
        violations = {
            'status': verification.get('status'),
            'found_records': verification.get('found', []),
            'summary': verification.get('summary', {}),
            'anonymized_records': rds_scan.get('anonymized_records', [])
        }
        
        return violations
    except Exception as e:
        return {"error": f"위반 사항 조회 실패: {e}"}


@app.post("/api/scan/rds-via-collector", response_model=RDSCollectorScanResponse)
def scan_rds_via_collector_endpoint(req: RDSCollectorScanRequest = Body(...)):
    """
    Collector API를 통한 RDS 익명화 검증 스캔
    
    1. Collector에서 RDS 인스턴스 목록 조회
    2. 각 RDS 인스턴스에서 테이블 데이터 수집
    3. 익명화 레코드 탐지 및 잔존 데이터 검증
    4. 통합 리포트 생성
    
    **장점:**
    - AWS 계정 정보를 Analyzer에서 관리할 필요 없음
    - Collector가 RDS 메타데이터를 자동으로 제공
    - 보안 강화 (DB 비밀번호만 전달)
    """
    try:
        print(f"\n[API] Collector 기반 RDS 익명화 스캔 시작")
        print(f"  - Collector: {req.collector_api}")
        print(f"  - 대상 RDS: {len(req.rds_configs)}개")
        
        from rds_collector_based_scanner import scan_rds_via_collector
        
        # 스캔 실행
        result = scan_rds_via_collector(
            collector_api=req.collector_api,
            db_configs=req.rds_configs,
            target_tables=req.target_tables
        )
        
        if 'error' in result:
            return RDSCollectorScanResponse(
                ok=False,
                error=result['error']
            )
        
        # 리포트 저장
        report_path = RESULTS_DIR / "rds_collector_scan_report.json"
        report_path.write_text(
            json.dumps(result, ensure_ascii=False, indent=2),
            encoding='utf-8'
        )
        
        print(f"\n[API] 스캔 완료")
        print(f"  - 익명화 레코드: {result['summary']['total_anonymized']}개")
        print(f"  - 잔존 데이터: {result['summary']['total_violations']}개")
        print(f"  - 상태: {result['summary']['status']}")
        print(f"  - 리포트: {report_path.resolve()}")
        
        return RDSCollectorScanResponse(
            ok=True,
            result=result,
            report_path=str(report_path.resolve())
        )
    
    except Exception as e:
        import traceback
        error_msg = f"{str(e)}\n\n{traceback.format_exc()}"
        print(f"[API] RDS 스캔 실패:\n{error_msg}")
        
        return RDSCollectorScanResponse(
            ok=False,
            error=error_msg
        )


@app.get("/api/scan/rds-via-collector/report")
def get_rds_collector_report():
    """Collector 기반 RDS 익명화 검증 리포트 조회"""
    report_path = RESULTS_DIR / "rds_collector_scan_report.json"
    
    if not report_path.exists():
        return {"error": "리포트가 존재하지 않습니다. 먼저 스캔을 실행하세요."}
    
    try:
        data = json.loads(report_path.read_text(encoding='utf-8'))
        return data
    except Exception as e:
        return {"error": f"리포트 읽기 실패: {e}"}


@app.get("/api/scan/rds-via-collector/violations")
def get_rds_collector_violations():
    """Collector 기반 RDS 익명화 위반 사항만 조회"""
    report_path = RESULTS_DIR / "rds_collector_scan_report.json"
    
    if not report_path.exists():
        return {"error": "리포트가 존재하지 않습니다."}
    
    try:
        data = json.loads(report_path.read_text(encoding='utf-8'))
        
        # 모든 인스턴스의 위반 사항 수집
        all_violations = []
        
        for instance_result in data.get('results', []):
            if 'verification' not in instance_result:
                continue
            
            verification = instance_result['verification']
            if verification.get('status') == 'violation':
                found_records = verification.get('found', [])
                
                for record in found_records:
                    record['db_identifier'] = instance_result.get('db_identifier')
                    all_violations.append(record)
        
        return {
            'status': 'violation' if all_violations else 'ok',
            'total_violations': len(all_violations),
            'violations': all_violations,
            'summary': data.get('summary', {})
        }
    
    except Exception as e:
        return {"error": f"위반 사항 조회 실패: {e}"}


@app.get("/api/scan/rds-via-collector/instances")
def get_rds_collector_instances(collector_api: str = Query(..., description="Collector API 주소")):
    """
    Collector에서 RDS 인스턴스 목록 조회 (스캔 전 확인용)
    
    이 API로 먼저 RDS 목록을 확인한 후, 필요한 인스턴스만 스캔할 수 있습니다.
    """
    try:
        from rds_collector_based_scanner import CollectorBasedRDSScanner
        
        scanner = CollectorBasedRDSScanner(collector_api)
        instances = scanner.get_rds_instances()
        
        # 필요한 정보만 추출 - 두 가지 필드명 형식 모두 지원
        simplified = []
        for inst in instances:
            # CamelCase와 snake_case 모두 지원
            db_id = inst.get('DBInstanceIdentifier') or inst.get('db_instance_identifier')
            
            # Endpoint는 객체일 수도, 분리된 필드일 수도 있음
            endpoint_data = inst.get('Endpoint', {})
            endpoint = endpoint_data.get('Address') if endpoint_data else inst.get('endpoint_address')
            port = endpoint_data.get('Port') if endpoint_data else inst.get('endpoint_port')
            
            engine = inst.get('Engine') or inst.get('engine')
            db_name = inst.get('DBName') or inst.get('db_name')
            status = inst.get('DBInstanceStatus') or inst.get('status')
            
            simplified.append({
                'db_identifier': db_id,
                'endpoint': endpoint,
                'port': port,
                'engine': engine,
                'db_name': db_name,
                'status': status
            })
        
        return {
            'collector_api': collector_api,
            'total_instances': len(simplified),
            'instances': simplified
        }
    
    except Exception as e:
        return {"error": f"RDS 인스턴스 조회 실패: {e}"}


@app.post("/api/v2/scan/rds-auto", response_model=RDSCollectorScanResponse)
def scan_rds_auto_endpoint(req: RDSCollectorScanRequestV2 = Body(...)):
    """
    [v2] Collector 기반 RDS 익명화 검증 스캔 (자동 메타데이터 활용 + 전체 자동 스캔)
    
    **개선 사항:**
    - ✅ RDS 연결 정보(endpoint, port, db_name) 자동 수집
    - ✅ Collector에서 찾은 모든 RDS 자동 스캔
    - ✅ password만 입력하면 자동 연결
    - ✅ 기본 계정(madeit/madeit1022!) 사용
    
    **사용 예시:**
    ```json
    {
      "collector_api": "http://211.44.183.248:8000"
    }
    ```
    
    특정 RDS에 다른 비밀번호 사용:
    ```json
    {
      "collector_api": "http://211.44.183.248:8000",
      "passwords": {"my-rds-1": "custom_password"}
    }
    ```
    """
    try:
        print(f"\n[API v2] 자동 RDS 익명화 스캔 시작")
        print(f"  - Collector: {req.collector_api}")
        print(f"  - 대상 RDS: Collector에서 찾은 전체 RDS 자동 스캔")
        print(f"  - 기본 계정: {req.default_user}/{req.default_password}")
        
        from rds_collector_based_scanner_v2 import scan_rds_via_collector_v2
        
        # 스캔 실행 (db_identifiers=None으로 전체 스캔)
        result = scan_rds_via_collector_v2(
            collector_api=req.collector_api,
            db_identifiers=None,  # 전체 RDS 자동 스캔
            passwords=req.passwords,
            target_tables=req.target_tables,
            default_user=req.default_user,
            default_password=req.default_password
        )
        
        if 'error' in result:
            return RDSCollectorScanResponse(
                ok=False,
                error=result['error']
            )
        
        # 리포트 저장
        report_path = RESULTS_DIR / "rds_auto_scan_report.json"
        report_path.write_text(
            json.dumps(result, ensure_ascii=False, indent=2),
            encoding='utf-8'
        )
        
        print(f"\n[API v2] 스캔 완료")
        print(f"  - 스캔된 인스턴스: {result.get('instances_scanned', 0)}개")
        print(f"  - 익명화 레코드: {result['summary']['total_anonymized']}개")
        print(f"  - 잔존 데이터: {result['summary']['total_violations']}개")
        print(f"  - 상태: {result['summary']['status']}")
        print(f"  - 리포트: {report_path.resolve()}")
        
        return RDSCollectorScanResponse(
            ok=True,
            result=result,
            report_path=str(report_path.resolve())
        )
    
    except Exception as e:
        import traceback
        error_msg = f"{str(e)}\n\n{traceback.format_exc()}"
        print(f"[API v2] RDS 스캔 실패:\n{error_msg}")
        
        return RDSCollectorScanResponse(
            ok=False,
            error=error_msg
        )


@app.get("/api/v2/scan/rds-auto/report")
def get_rds_auto_report():
    """[v2] 자동 RDS 익명화 검증 리포트 조회"""
    report_path = RESULTS_DIR / "rds_auto_scan_report.json"
    
    if not report_path.exists():
        return {"error": "리포트가 존재하지 않습니다. 먼저 스캔을 실행하세요."}
    
    try:
        data = json.loads(report_path.read_text(encoding='utf-8'))
        return data
    except Exception as e:
        return {"error": f"리포트 읽기 실패: {e}"}


@app.get("/api/v2/scan/rds-auto/violations")
def get_rds_auto_violations():
    """[v2] 자동 RDS 익명화 위반 사항만 조회"""
    report_path = RESULTS_DIR / "rds_auto_scan_report.json"
    
    if not report_path.exists():
        return {"error": "리포트가 존재하지 않습니다."}
    
    try:
        data = json.loads(report_path.read_text(encoding='utf-8'))
        
        # 모든 인스턴스의 위반 사항 수집
        all_violations = []
        
        for instance_result in data.get('results', []):
            if 'verification' not in instance_result:
                continue
            
            verification = instance_result['verification']
            if verification.get('status') == 'violation':
                found_records = verification.get('found', [])
                
                for record in found_records:
                    record['db_identifier'] = instance_result.get('db_identifier')
                    all_violations.append(record)
        
        return {
            'status': 'violation' if all_violations else 'ok',
            'total_violations': len(all_violations),
            'violations': all_violations,
            'summary': data.get('summary', {})
        }
    
    except Exception as e:
        return {"error": f"위반 사항 조회 실패: {e}"}


class CrossCheckRequest(BaseModel):
    collector_api: str = Field(..., description="Collector API 주소")
    bucket_names: Optional[List[str]] = Field(None, description="검색할 S3 버킷 목록 (None=전체)")
    file_extensions: Optional[List[str]] = Field(None, description="파일 확장자 필터 (예: ['.csv', '.json'])")
    max_files_per_bucket: int = Field(100, description="버킷당 최대 검색 파일 수")

@app.post("/api/v2/scan/cross-check")
def cross_check_rds_s3(req: CrossCheckRequest = Body(...)):
    """
    [v2] RDS-S3 교차 검증
    
    RDS에서 발견된 익명화 ID를 Collector API를 통해 S3 원본 파일에서 직접 검색
    """
    try:
        from s3_id_matcher import search_ids_in_s3_via_collector
        
        # RDS 스캔 결과에서 ID 추출
        rds_report_path = RESULTS_DIR / "rds_auto_scan_report.json"
        
        if not rds_report_path.exists():
            return {
                "error": "RDS 스캔 결과가 없습니다. 먼저 /api/v2/scan/rds-auto를 실행하세요."
            }
        
        rds_data = json.loads(rds_report_path.read_text(encoding='utf-8'))
        
        # 모든 익명화 레코드의 original_id 수집
        all_ids = set()
        for result in rds_data.get('results', []):
            for anon_record in result.get('anonymized_records', []):
                original_id = anon_record.get('original_id')
                if original_id:
                    # 정수로 변환 가능한 경우만 추가
                    try:
                        all_ids.add(int(original_id))
                    except (ValueError, TypeError):
                        continue
        
        rds_ids = sorted(list(all_ids))
        
        if not rds_ids:
            return {
                "ok": True,
                "message": "RDS에서 익명화된 ID가 발견되지 않았습니다.",
                "rds_ids": [],
                "s3_matches": {
                    'matched_files': [],
                    'summary': {
                        'total_rds_ids': 0,
                        'matched_ids_count': 0,
                        'status': 'ok'
                    }
                }
            }
        
        print(f"\n[교차 검증] RDS ID {len(rds_ids)}개를 S3에서 직접 검색 중...")
        print(f"[검색 ID] {rds_ids}")
        print(f"[Collector API] {req.collector_api}")
        
        # Collector API를 통해 S3 원본 파일 직접 검색
        s3_matches = search_ids_in_s3_via_collector(
            collector_api=req.collector_api,
            rds_ids=rds_ids,
            bucket_names=req.bucket_names,
            file_extensions=req.file_extensions,
            max_files_per_bucket=req.max_files_per_bucket
        )
        
        # 교차 검증 리포트 저장
        cross_check_report = {
            'scan_time': datetime.now().isoformat(),
            'rds_scan': {
                'report_path': str(rds_report_path),
                'ids_found': rds_ids,
                'total_ids': len(rds_ids)
            },
            's3_scan': {
                'collector_api': req.collector_api,
                'bucket_names': req.bucket_names or 'all',
                'matches': s3_matches
            },
            'cross_check_summary': {
                'rds_ids_checked': len(rds_ids),
                's3_matches_found': s3_matches['summary']['matched_ids_count'],
                'matched_ids': s3_matches.get('found_ids', []),
                'unmatched_ids': s3_matches.get('not_found_ids', []),
                'matched_files_count': s3_matches['summary']['matched_files_count'],
                'status': 'violation' if s3_matches['summary']['matched_ids_count'] > 0 else 'ok',
                'risk_level': 'HIGH' if s3_matches['summary']['matched_ids_count'] > 0 else 'LOW'
            }
        }
        
        cross_check_path = RESULTS_DIR / "cross_check_report.json"
        cross_check_path.write_text(
            json.dumps(cross_check_report, ensure_ascii=False, indent=2),
            encoding='utf-8'
        )
        
        print(f"\n[교차 검증 완료]")
        print(f"  - RDS ID: {len(rds_ids)}개")
        print(f"  - S3 매칭: {s3_matches['summary']['matched_ids_count']}개")
        print(f"  - 매칭 파일: {s3_matches['summary']['matched_files_count']}개")
        print(f"  - 상태: {cross_check_report['cross_check_summary']['status']}")
        print(f"  - 리포트: {cross_check_path}")
        
        return {
            "ok": True,
            "rds_ids": rds_ids,
            "s3_matches": s3_matches,
            "summary": cross_check_report['cross_check_summary'],
            "report_path": str(cross_check_path)
        }
    
    except Exception as e:
        import traceback
        error_msg = f"{str(e)}\n\n{traceback.format_exc()}"
        print(f"[교차 검증 실패]\n{error_msg}")
        
        return {
            "ok": False,
            "error": error_msg
        }


@app.get("/api/v2/scan/cross-check/report")
def get_cross_check_report():
    """[v2] RDS-S3 교차 검증 리포트 조회"""
    report_path = RESULTS_DIR / "cross_check_report.json"
    
    if not report_path.exists():
        return {"error": "교차 검증 리포트가 없습니다. 먼저 /api/v2/scan/cross-check를 실행하세요."}
    
    try:
        data = json.loads(report_path.read_text(encoding='utf-8'))
        return data
    except Exception as e:
        return {"error": f"리포트 읽기 실패: {e}"}