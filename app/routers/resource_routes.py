"""
资源路由：当前用户 / 资源 A / 资源 B。

全部需要登录：每个函数显式挂 get_current_account。
"""

from fastapi import APIRouter, Depends, HTTPException, status

from app import store
from app.auth import get_current_account
from app.permissions import resource_b_access_mode

router = APIRouter(prefix="/api", tags=["resource"])

# 公告板 Mock 数据（资源 A）
ANNOUNCEMENTS = [
    {"id": 1, "title": "欢迎使用登录授权 Demo", "author": "admin", "time": "2026-08-31",
     "body": "本系统演示基于角色的资源访问控制。默认用户可阅读公告板，仅管理员可访问管理面板。"},
    {"id": 2, "title": "安全说明", "author": "admin", "time": "2026-08-31",
     "body": "所有权限判定均在服务端完成，前端按钮置灰仅为体验优化，无法绕过后端校验。"},
]


@router.get("/me")
async def me(account: dict = Depends(get_current_account)):
    """当前用户信息（含最新 role / capabilities，前端据此渲染界面）。"""
    return {"user": store.public_view(account)}


@router.get("/resource/a")
async def resource_a(account: dict = Depends(get_current_account)):
    """资源 A（社区公告板）：任意有效登录用户可读。"""
    return {
        "resource": "A",
        "name": "社区公告板",
        "announcements": ANNOUNCEMENTS,
        "viewer": account["username"],
    }


@router.get("/resource/b")
async def resource_b(account: dict = Depends(get_current_account)):
    """资源 B（管理面板）：admin 天然可见；非 admin 需被显式授权，否则 403。

    关键：能否「看见」与能否「改」分离 ——
    本端点只控制可见性，写操作全部收敛到 /api/admin/* 且仅 admin。
    """
    caps = account["capabilities"]
    if not caps.get("viewResourceB"):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail={"error": "权限不足：资源 B 需要 admin 角色或管理员授予的查看权限", "code": "FORBIDDEN"},
        )

    mode = resource_b_access_mode(account)
    stats = store.stats()
    return {
        "resource": "B",
        "name": "管理面板",
        "viewer": account["username"],
        "access": {
            "mode": mode,
            "readOnly": mode != "admin",
            "capabilities": caps,
        },
        "metrics": {
            "totalUsers": stats["totalUsers"],
            "adminCount": stats["adminCount"],
            "pendingReviewCount": stats["pendingReviewCount"],
            "grantedCount": stats["grantedCount"],
            "bannedCount": stats["bannedCount"],
        },
        "users": store.list_all(),
        "pendingReview": store.list_pending_review(),
        "recentRegistrations": stats["recentRegistrations"],
        "systemLog": [
            {"time": "2026-08-31 12:00", "event": "系统初始化", "detail": "seed 账号已就绪"},
            {"time": "2026-08-31 12:01", "event": "权限策略", "detail": "资源B：admin 完全控制，被授权用户只读"},
        ],
    }
