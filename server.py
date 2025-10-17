# server.py
# FastAPI for AEGIS Analyzer (front-only).
# - 표준 결과 경로: ./var/results/
# - 파일 단위(front-list/...) + 리소스(source) 단위(source-summary/...) 동시 지원
# - collector 트리거는 var/results/results_all.json 으로 고정, 그 옆에 results_front.json 생성됨
# - 기본=전체 리소스: services 미지정([]) 또는 ["all"] / ["*"] 이면 --services 전달 안함

import os, io, csv, json, hashlib, subprocess, sys, tarfile, tempfile, shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Literal, Tuple

from fastapi import FastAPI, Query, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse
from pydantic import BaseModel, Field

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
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
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
