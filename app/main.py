"""
FastAPI 入口：建库 → 创建应用 →（由 uvicorn 启动）。

启动命令：uvicorn app.main:app --reload
"""

from pathlib import Path

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.db import init_db
from app.routers import admin_routes, auth_routes, resource_routes

# 静态前端目录（项目根/public）
PUBLIC_DIR = Path(__file__).resolve().parent.parent / "public"


def create_app() -> FastAPI:
    init_db()  # 启动时建表 + seed admin（幂等）

    app = FastAPI(title="登录授权 Demo")

    # 注册三个路由
    app.include_router(auth_routes.router)
    app.include_router(resource_routes.router)
    app.include_router(admin_routes.router)

    # ============ 错误结构统一 ============
    # FastAPI 默认把 HTTPException(detail={...}) 包成 {"detail": {...}}，
    # 把 Pydantic 422 包成 {"detail": [{loc,msg,type}]}；
    # 但前端只读 data.error / data.code，所以这里拍平成 {error, code}。

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request, exc):
        detail = exc.detail
        # 我们抛的 HTTPException 已带 {error, code}，直接透传
        if isinstance(detail, dict) and "error" in detail:
            return JSONResponse(status_code=exc.status_code, content=detail)
        # 其他（如路由不存在的 404）→ 统一结构
        msg = detail if isinstance(detail, str) else "请求错误"
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": msg, "code": "HTTP_ERROR"},
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request, exc):
        # Pydantic 422 → {error, code}
        return JSONResponse(
            status_code=422,
            content={"error": "请求参数不合法（格式或长度不符）", "code": "INVALID_INPUT"},
        )

    # 挂静态前端：放在路由注册之后，/api/* 优先匹配路由，其余路径走静态文件
    # html=True：根路径 "/" 返回 index.html
    app.mount("/", StaticFiles(directory=PUBLIC_DIR, html=True), name="static")

    return app


app = create_app()
