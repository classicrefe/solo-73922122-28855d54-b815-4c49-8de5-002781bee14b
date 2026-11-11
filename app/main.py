"""FastAPI 入口：规则差分页面与 JSON API。"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .collector.routes import get_collect_page, router as deny_router
from .engine import ValidationFailure, analyze
from .example_data import EXAMPLE_PAYLOAD

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(
    title="防火墙运维台",
    description="规则变更精确差分 + deny.log 被拒连接采集排查。",
    version="2.0.0",
)


class DiffRequest(BaseModel):
    old: str = Field(..., description="旧规则集 JSON 文本（数组，最多 20 条）")
    new: str = Field(..., description="新规则集 JSON 文本（数组，最多 20 条）")


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/deny", include_in_schema=False)
def deny_collect_page() -> FileResponse:
    return get_collect_page()


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
app.include_router(deny_router)


@app.get("/api/example")
def get_example() -> JSONResponse:
    """提供可一键载入的重叠规则示例。"""
    return JSONResponse(EXAMPLE_PAYLOAD)


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/analyze")
def post_analyze(req: DiffRequest) -> JSONResponse:
    try:
        result = analyze(req.old, req.new)
    except ValidationFailure as exc:
        # 输入无效：返回带位置的结构化错误，前端据此清除旧结果
        return JSONResponse(status_code=400,
                            content={"ok": False, "errors": exc.errors})
    return JSONResponse(content={"ok": True, "result": result})


@app.exception_handler(Exception)
def unhandled(_request, exc: Exception) -> JSONResponse:  # pragma: no cover
    return JSONResponse(status_code=500,
                        content={"ok": False, "errors": [
                            {"sheet": None, "field": None,
                             "message": f"服务器内部错误：{type(exc).__name__}: {exc}"}]})
