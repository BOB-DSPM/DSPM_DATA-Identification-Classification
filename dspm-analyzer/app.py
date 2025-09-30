from __future__ import annotations

import os, uuid, json, datetime as dt
from typing import Optional, Dict, Any, List, Tuple

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from sqlalchemy import (
    create_engine, text, MetaData, Table, Column,
    String, BigInteger, DateTime, Boolean, JSON, Float, UniqueConstraint
)
from sqlalchemy.orm import sessionmaker

# ==================== Config ====================
PG_DSN = os.getenv("PG_DSN", "postgresql://dspm:dspm@postgres:5432/dspm")

engine = create_engine(PG_DSN, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
metadata = MetaData()

# ==================== Tables ====================
data_object = Table(
    "data_object", metadata,
    Column("id", String, primary_key=True),
    Column("source_id", String, nullable=False),
    Column("object_type", String, nullable=False),     # e.g., bucket / rds-instance / image
    Column("locator", String, nullable=False),         # unique; e.g., s3://bucket, ecr://repo:tag
    Column("parent_locator", String),
    Column("bytes", BigInteger),
    Column("extra", JSON),                             # arbitrary meta
    Column("first_seen", DateTime, default=dt.datetime.utcnow),
    Column("last_scanned", DateTime),
    Column("last_modified", DateTime),
    Column("etag", String),
    Column("checksum", String),
    Column("version", String),
    UniqueConstraint("locator", name="uq_locator")
)

object_profile = Table(
    "object_profile", metadata,
    Column("object_id", String, primary_key=True),
    Column("bytes", BigInteger),
    Column("line_count", BigInteger),
    Column("avg_line_len", Float),
    Column("max_line_len", BigInteger),
    Column("ratio_digit", Float),
    Column("ratio_alpha", Float),
    Column("ratio_symbol", Float),
    Column("has_csv_header", Boolean),
    Column("profiled_at", DateTime, default=dt.datetime.utcnow),
)

pseudonymization_guard = Table(
    "pseudonymization_guard", metadata,
    Column("object_id", String, primary_key=True),
    Column("is_pseudonymized", Boolean, nullable=False),
    Column("mapping_locator", String),
    Column("separated", Boolean),
    Column("separation_reason", String),
    Column("checked_at", DateTime, default=dt.datetime.utcnow),
)

metadata.create_all(engine)

# ==================== Schemas ====================
# Collector가 보내는 Asset / BulkPayload
class AssetIn(BaseModel):
    kind: str
    locator: str
    name: str
    region: str
    bytes: Optional[int] = None
    meta: Dict[str, Any] = Field(default_factory=dict)

class BulkIn(BaseModel):
    source_id: str
    items: List[AssetIn]

# 수동 단건 테스트용
class MetaIn(BaseModel):
    source_id: str
    object_type: str
    locator: str
    parent_locator: Optional[str] = None
    bytes: Optional[int] = None
    extra: Dict[str, Any] = Field(default_factory=dict)

class CollectResp(BaseModel):
    object_id: str
    message: str

# ==================== Helpers ====================
def _parse_iso8601(s: Optional[str]) -> Optional[dt.datetime]:
    if not s:
        return None
    try:
        s2 = s.replace("Z", "+00:00")
        return dt.datetime.fromisoformat(s2)
    except Exception:
        return None

def profile_text(s: str) -> dict:
    if not s:
        return dict(line_count=0, avg_line_len=0.0, max_line_len=0,
                    ratio_digit=0.0, ratio_alpha=0.0, ratio_symbol=0.0, has_csv_header=False)
    lines = s.splitlines()[:5000]
    ln = len(lines)
    avg_len = sum(len(x) for x in lines)/ln if ln else 0.0
    max_len = max((len(x) for x in lines), default=0)
    sample = s[:200_000]
    total = len(sample) or 1
    digits = sum(c.isdigit() for c in sample)/total
    alpha  = sum(c.isalpha() for c in sample)/total
    symbols= max(0.0, 1.0 - digits - alpha)
    has_csv = (',' in lines[0]) if ln else False
    return dict(line_count=ln, avg_line_len=avg_len, max_line_len=max_len,
                ratio_digit=digits, ratio_alpha=alpha, ratio_symbol=symbols, has_csv_header=has_csv)

def pseudonymization_from_extra(extra: dict) -> Tuple[bool, Optional[str], Optional[bool], Optional[str]]:
    mapping = (extra or {}).get("mapping_locator")
    if not mapping:
        return False, None, None, None
    sep = (extra or {}).get("separated_by", {}) or {}
    separated = any([
        sep.get("different_account"),
        sep.get("different_kms_key"),
        sep.get("network_boundary"),
    ])
    reason = "별도 계정/KMS/네트워크 분리 충족" if separated else "분리 근거 부족"
    return True, mapping, separated, reason

def _merge_extra_for_asset(item: AssetIn) -> Dict[str, Any]:
    merged = dict(item.meta or {})
    merged.setdefault("display_name", item.name)
    merged.setdefault("region", item.region)
    return merged

# ==================== FastAPI ====================
app = FastAPI(title="DSPM Analyzer (Receiver+Scanner)", version="0.4")

@app.get("/health")
def health():
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    return {"ok": True, "pg_dsn": PG_DSN}

# ----------- Collector 벌크 수신 -----------
@app.post("/api/assets:bulk")
@app.post("/api/assets/save")
def ingest_bulk(payload: BulkIn):
    session = SessionLocal()
    now = dt.datetime.utcnow()
    created = 0
    updated = 0
    profiled = 0
    guarded = 0

    try:
        for item in payload.items:
            extra = _merge_extra_for_asset(item)
            last_modified = _parse_iso8601(extra.get("last_modified"))
            etag = extra.get("etag")
            checksum = extra.get("checksum")
            version = extra.get("version")

            row = session.execute(
                text("SELECT id FROM data_object WHERE locator=:loc"),
                {"loc": item.locator}
            ).fetchone()

            if row:
                obj_id = row[0]
                session.execute(text("""
                    UPDATE data_object
                       SET source_id=:sid,
                           object_type=:ot,
                           bytes=:b,
                           extra=:e,
                           last_scanned=:now,
                           last_modified=:lm,
                           etag=:etag,
                           checksum=:chk,
                           version=:ver
                     WHERE id=:id
                """), {
                    "sid": payload.source_id, "ot": item.kind, "b": item.bytes,
                    "e": json.dumps(extra), "now": now, "lm": last_modified,
                    "etag": etag, "chk": checksum, "ver": version, "id": obj_id
                })
                updated += 1
            else:
                obj_id = str(uuid.uuid4())
                session.execute(text("""
                    INSERT INTO data_object
                      (id, source_id, object_type, locator, parent_locator, bytes, extra,
                       first_seen, last_scanned, last_modified, etag, checksum, version)
                    VALUES
                      (:id,:sid,:ot,:loc,:pl,:b,:e,:fs,:ls,:lm,:etag,:chk,:ver)
                """), {
                    "id": obj_id, "sid": payload.source_id, "ot": item.kind,
                    "loc": item.locator, "pl": None, "b": item.bytes,
                    "e": json.dumps(extra), "fs": now, "ls": now, "lm": last_modified,
                    "etag": etag, "chk": checksum, "ver": version
                })
                created += 1

            sample = extra.get("sample") or ""
            if isinstance(sample, str) and sample:
                prof = profile_text(sample)
                session.execute(text("""
                    INSERT INTO object_profile(object_id, bytes, line_count, avg_line_len, max_line_len,
                                               ratio_digit, ratio_alpha, ratio_symbol, has_csv_header, profiled_at)
                    VALUES(:oid,:b,:lc,:avg,:max,:rd,:ra,:rs,:csv,:now)
                    ON CONFLICT (object_id) DO UPDATE SET
                      bytes=EXCLUDED.bytes, line_count=EXCLUDED.line_count,
                      avg_line_len=EXCLUDED.avg_line_len, max_line_len=EXCLUDED.max_line_len,
                      ratio_digit=EXCLUDED.ratio_digit, ratio_alpha=EXCLUDED.ratio_alpha,
                      ratio_symbol=EXCLUDED.ratio_symbol, has_csv_header=EXCLUDED.has_csv_header,
                      profiled_at=EXCLUDED.profiled_at
                """), {
                    "oid": obj_id, "b": item.bytes or 0,
                    "lc": prof["line_count"], "avg": prof["avg_line_len"], "max": prof["max_line_len"],
                    "rd": prof["ratio_digit"], "ra": prof["ratio_alpha"], "rs": prof["ratio_symbol"],
                    "csv": prof["has_csv_header"], "now": now
                })
                profiled += 1

            has_map, mapping_loc, separated, sep_reason = pseudonymization_from_extra(extra)
            if has_map:
                session.execute(text("""
                    INSERT INTO pseudonymization_guard(object_id,is_pseudonymized,mapping_locator,separated,separation_reason,checked_at)
                    VALUES(:oid,true,:map,:sep,:reas,:now)
                    ON CONFLICT (object_id) DO UPDATE SET
                      is_pseudonymized=EXCLUDED.is_pseudonymized,
                      mapping_locator=EXCLUDED.mapping_locator,
                      separated=EXCLUDED.separated,
                      separation_reason=EXCLUDED.separation_reason,
                      checked_at=EXCLUDED.checked_at
                """), {
                    "oid": obj_id, "map": mapping_loc,
                    "sep": bool(separated), "reas": sep_reason, "now": now
                })
                guarded += 1

        session.commit()
        return {
            "ok": True,
            "created": created,
            "updated": updated,
            "profiled": profiled,
            "guarded": guarded
        }
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=f"bulk ingest failed: {e}")
    finally:
        session.close()

# ----------- 기존 개별 메타 수집 (테스트용) -----------
@app.post("/collect/meta", response_model=CollectResp)
def collect_meta(m: MetaIn):
    session = SessionLocal()
    try:
        obj_id = str(uuid.uuid4())
        session.execute(text("""
            INSERT INTO data_object(id,source_id,object_type,locator,bytes,extra,first_seen,last_scanned)
            VALUES(:id,:sid,:ot,:loc,:b,:e,:fs,:ls)
        """), {
            "id": obj_id, "sid": m.source_id, "ot": m.object_type,
            "loc": m.locator, "b": m.bytes, "e": json.dumps(m.extra),
            "fs": dt.datetime.utcnow(), "ls": dt.datetime.utcnow()
        })
        session.commit()
        return CollectResp(object_id=obj_id, message="stored")
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=f"collect failed: {e}")
    finally:
        session.close()

# ----------- 조회/리포트 API -----------
@app.get("/profiles/{locator:path}")
def get_profile(locator: str):
    with engine.connect() as conn:
        row = conn.execute(text("""
            SELECT o.locator, p.* FROM object_profile p
            JOIN data_object o ON o.id=p.object_id
            WHERE o.locator=:loc
        """), {"loc": locator}).fetchone()
    if not row:
        raise HTTPException(404, "profile not found")
    return dict(row._mapping)

@app.get("/guards/violations")
def guard_violations(limit: int = Query(50, le=200)):
    with engine.connect() as conn:
        rows = conn.execute(text("""
          SELECT o.locator, g.mapping_locator, g.separated, g.separation_reason, g.checked_at
          FROM pseudonymization_guard g
          JOIN data_object o ON o.id = g.object_id
          WHERE g.is_pseudonymized = true AND COALESCE(g.separated, false) = false
          ORDER BY g.checked_at DESC
          LIMIT :lim
        """), {"lim": limit}).fetchall()
    return [dict(r._mapping) for r in rows]

@app.get("/guards/status")
def guard_status():
    with engine.connect() as conn:
        total = conn.execute(text("""
          SELECT COUNT(*) FROM pseudonymization_guard WHERE is_pseudonymized=true
        """)).scalar() or 0
        ok = conn.execute(text("""
          SELECT COUNT(*) FROM pseudonymization_guard WHERE is_pseudonymized=true AND COALESCE(separated,false)=true
        """)).scalar() or 0
    bad = total - ok
    return {"pseudonymized_total": total, "separated_ok": ok, "separated_missing": bad}
