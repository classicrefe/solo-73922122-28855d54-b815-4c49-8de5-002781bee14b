"""采集功能的 FastAPI 路由。

  POST /api/deny/collect          触发一轮采集（两进程并发时第二个被拒绝）
  GET  /api/deny/status           目录、进度（按文件身份）、坏行、计数
  GET  /api/deny/events           分页查询被拒连接，可按规则/IP 过滤
  GET  /api/deny/errors           坏行列表（文件与字节位置）
  POST /api/deny/errors/clear     清除坏行标记（修复日志后可重新采集）
  GET  /deny                      采集页
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Query
from fastapi.responses import FileResponse, JSONResponse

from . import db
from .config import get_settings
from .ingest import AlreadyRunning, discover_files, run_ingestion

router = APIRouter(prefix="/api/deny", tags=["deny-collector"])

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


def _iso_utc(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


@router.post("/collect")
def trigger_collect() -> JSONResponse:
    try:
        report = run_ingestion()
    except AlreadyRunning as exc:
        # 并发采集被互斥锁拒绝：不排队、不报错 500
        return JSONResponse(status_code=409,
                            content={"ok": False, "busy": True,
                                     "message": str(exc)})
    return JSONResponse(content=report)


@router.get("/status")
def get_status() -> JSONResponse:
    settings = get_settings()
    db.init_db(settings.db_path)
    files_meta: list[dict] = []
    live_paths = discover_files(settings.log_dir)
    with db.connect(settings.db_path) as conn:
        progress_rows = {
            (r["file_dev"], r["file_ino"]): r
            for r in db.all_progress(conn)
        }
        error_rows = {(r["file_dev"], r["file_ino"]): r
                      for r in db.all_errors(conn)}
        total_events = db.count_events(conn)
        total_errors = db.count_errors(conn)

        for path in live_paths:
            try:
                st = path.stat()
            except FileNotFoundError:
                continue
            key = (st.st_dev, st.st_ino)
            prog = progress_rows.get(key)
            err = error_rows.get(key)
            files_meta.append({
                "fileName": path.name,
                "fileDev": st.st_dev,
                "fileIno": st.st_ino,
                "fileSize": st.st_size,
                "offsetBytes": int(prog["offset_bytes"]) if prog else 0,
                "lineCount": int(prog["line_count"]) if prog else 0,
                "updatedAt": prog["updated_at"] if prog else None,
                "hasError": err is not None,
                "error": dict(err) if err else None,
            })

        # 进度里存在、但目录中已找不到的文件身份（轮转文件被清理等）
        live_keys = {(f["fileDev"], f["fileIno"]) for f in files_meta}
        stale = []
        for key, row in progress_rows.items():
            if key not in live_keys:
                stale.append({
                    "fileName": row["file_name"],
                    "fileDev": row["file_dev"],
                    "fileIno": row["file_ino"],
                    "offsetBytes": row["offset_bytes"],
                    "lineCount": row["line_count"],
                    "updatedAt": row["updated_at"],
                    "hasError": key in error_rows,
                })

        errors = [dict(r) for r in db.all_errors(conn)]

    return JSONResponse(content={
        "ok": True,
        "logDir": str(settings.log_dir),
        "dbPath": str(settings.db_path),
        "logDirExists": settings.log_dir.is_dir(),
        "totalEvents": total_events,
        "totalErrors": total_errors,
        "files": files_meta,
        "staleProgress": stale,
        "errors": errors,
    })


@router.get("/events")
def get_events(page: int = Query(1, ge=1),
               page_size: int = Query(20, ge=1, le=200),
               rule_id: Optional[str] = None,
               src_ip: Optional[str] = None,
               dst_ip: Optional[str] = None) -> JSONResponse:
    settings = get_settings()
    db.init_db(settings.db_path)
    with db.connect(settings.db_path) as conn:
        rows, total = db.query_events(conn, page, page_size,
                                      rule_id=rule_id, src_ip=src_ip,
                                      dst_ip=dst_ip)
    items = [{
        "id": r["id"],
        "tsUtc": r["ts_utc"],
        "tsIso": _iso_utc(r["ts_utc"]),
        "srcIp": r["src_ip"],
        "dstIp": r["dst_ip"],
        "dstPort": r["dst_port"],
        "ruleId": r["rule_id"],
        "source": {
            "file": r["source_file"],
            "lineNo": r["line_no"],
            "lineOffset": r["line_offset"],
            "fileDev": r["file_dev"],
            "fileIno": r["file_ino"],
        },
    } for r in rows]
    total_pages = (total + page_size - 1) // page_size if total else 0
    return JSONResponse(content={
        "ok": True, "page": page, "pageSize": page_size,
        "total": total, "totalPages": total_pages, "items": items,
    })


@router.get("/errors")
def get_errors() -> JSONResponse:
    settings = get_settings()
    db.init_db(settings.db_path)
    with db.connect(settings.db_path) as conn:
        rows = db.all_errors(conn)
    return JSONResponse(content={
        "ok": True,
        "items": [{
            "id": r["id"],
            "fileName": r["file_name"],
            "fileDev": r["file_dev"],
            "fileIno": r["file_ino"],
            "lineNo": r["line_no"],
            "lineOffset": r["line_offset"],
            "reason": r["reason"],
            "rawPreview": r["raw_preview"],
            "createdAt": r["created_at"],
        } for r in rows],
    })


@router.post("/errors/clear")
def post_clear_errors() -> JSONResponse:
    settings = get_settings()
    db.init_db(settings.db_path)
    with db.connect(settings.db_path) as conn:
        removed = db.clear_errors(conn)
    return JSONResponse(content={"ok": True, "cleared": removed})


def get_collect_page() -> FileResponse:
    return FileResponse(STATIC_DIR / "collect.html")
