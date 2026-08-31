"""
管理路由：用户清单 / 授权 / 封禁 / 删除 / 审核预览。

所有端点严格仅 admin（通过 require_capability / require_role 强制），
能力由服务端依据数据库最新记录推导，前端上报无效。
"""

from fastapi import APIRouter, Depends, HTTPException, status

from app import moderation
from app import store
from app.auth import require_capability, require_role
from app.schemas import BanRequest, GrantAccessRequest

router = APIRouter(prefix="/api", tags=["admin"])


def _resolve_target_id(user_id: str, account: dict) -> str:
    """管理操作目标校验：不能对自己操作（CANNOT_TARGET_SELF）。"""
    if user_id == account["id"]:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail={"error": "不能对自己执行该操作", "code": "CANNOT_TARGET_SELF"},
        )
    return user_id


def _send_manage_failure(result: dict):
    """把 store 返回的失败码映射为 HTTP 状态：USER_NOT_FOUND → 404，其余 → 403。"""
    code = result["code"]
    status_code = status.HTTP_404_NOT_FOUND if code == "USER_NOT_FOUND" else status.HTTP_403_FORBIDDEN
    raise HTTPException(status_code, detail={"error": result["message"], "code": code})


@router.get("/admin/users")
async def list_users(
    account: dict = Depends(require_capability("manageUsers", "权限不足：用户管理仅 admin 角色可用")),
):
    """全量用户清单（管理用）。"""
    stats = store.stats()
    return {"users": store.list_all(), "total": stats["totalUsers"]}


@router.patch("/admin/users/{user_id}/access")
async def set_access(
    user_id: str,
    body: GrantAccessRequest,
    account: dict = Depends(require_capability("grantResourceB", "权限不足：调整资源 B 访问权限仅 admin 角色可执行")),
):
    """授权/撤销「资源 B 只读访问」。只影响可见性，永不授予管理能力。"""
    _resolve_target_id(user_id, account)
    result = store.set_resource_b_access(user_id, body.granted)
    if not result["ok"]:
        _send_manage_failure(result)
    return {
        "message": "已授予资源 B 只读访问权限" if body.granted else "已撤销资源 B 访问权限",
        "user": result["user"],
    }


@router.patch("/admin/users/{user_id}/ban")
async def set_ban(
    user_id: str,
    body: BanRequest,
    account: dict = Depends(require_capability("banUser", "权限不足：封禁用户仅 admin 角色可执行")),
):
    """封禁/解封用户。封禁后已登录 token 立即失效（见 auth 账号中间件）。"""
    _resolve_target_id(user_id, account)
    result = store.set_banned(user_id, body.banned)
    if not result["ok"]:
        _send_manage_failure(result)
    return {
        "message": "用户已封禁（其已登录的令牌立即失效）" if body.banned else "用户已解封",
        "user": result["user"],
    }


@router.delete("/admin/users/{user_id}")
async def delete_user(
    user_id: str,
    account: dict = Depends(require_capability("deleteUser", "权限不足：删除用户仅 admin 角色可执行")),
):
    """删除用户（不可恢复）。admin 账号受保护（store 层拦截）。"""
    _resolve_target_id(user_id, account)
    result = store.remove_user(user_id)
    if not result["ok"]:
        _send_manage_failure(result)
    return {"message": "用户已删除", "user": result["user"]}


@router.get("/moderation/preview")
async def preview(
    username: str,
    account: dict = Depends(require_role("admin")),
):
    """管理员调试工具：实时查看用户名 LLM 违规判定结果（仅 admin）。"""
    if not username:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail={"error": "缺少 username 查询参数", "code": "INVALID_INPUT"},
        )
    verdict = await moderation.check_username(username)
    return {"username": username, **verdict}
