"""
鉴权模块：bcrypt 密码哈希 + JWT 签发/校验 + 三层 FastAPI 鉴权依赖。

三层鉴权（FastAPI 的 Depends 依赖链）：
  第1层 get_current_user     —— 解析 Authorization: Bearer 令牌，验签，取出快照
  第2层 get_current_account  —— 用快照 id 回数据库读【最新】记录（封禁/删除立即生效）
  第3层 require_role / require_capability —— 基于最新记录做角色/能力判定

安全要点：
  - JWT 验签必须显式 algorithms=["HS256"]（防 alg:none 攻击）
  - 权限判定永远基于第2层读到的数据库最新记录，绝不信任 token 里的 role 快照
"""

from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app import config
from app import store
from app.permissions import compute_capabilities

# ============ 常量 ============
SALT_ROUNDS = 10
TOKEN_TTL_SECONDS = 60 * 60 * 12  # 12 小时

# HTTPBearer：从请求头解析 "Authorization: Bearer <token>"。
# auto_error=False：缺头/格式错时不自动抛 401，而是把 credentials 置为 None，交给第1层统一处理。
_bearer = HTTPBearer(auto_error=False)


# ============ 密码哈希 ============
def hash_password(plain: str) -> str:
    """bcrypt 加盐哈希，返回哈希字符串。"""
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(SALT_ROUNDS)).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """校验明文密码是否匹配哈希。"""
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


# ============ JWT 签发 / 校验 ============
def create_token(payload: dict) -> str:
    """签发 JWT。payload 里带 id/username/role 快照。"""
    exp = datetime.now(timezone.utc) + timedelta(seconds=TOKEN_TTL_SECONDS)
    return jwt.encode({**payload, "exp": exp}, config.get_jwt_secret(), algorithm="HS256")


def decode_token(token: str) -> dict:
    """验签并解析 JWT，返回 payload dict；验签失败抛 jwt.PyJWTError（由调用方捕获）。"""
    return jwt.decode(token, config.get_jwt_secret(), algorithms=["HS256"])


# ============ 第1层：解析令牌 ============
async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> dict:
    """解析 Bearer token，返回快照 {id, username, role}。"""
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "未登录或缺少令牌", "code": "UNAUTHORIZED"},
        )
    try:
        return decode_token(credentials.credentials)
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "令牌已无效或过期", "code": "UNAUTHORIZED"},
        )


# ============ 第2层：回库读最新 ============
async def get_current_account(
    payload: dict = Depends(get_current_user),
) -> dict:
    """回数据库读最新用户记录，覆盖 token 快照。"""
    # 1. 回库读最新记录（不信 JWT 快照，删除/降级立即生效）
    account = store.find_by_id(payload["id"])
    if account is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "账号不存在或已被删除，请重新登录", "code": "ACCOUNT_NOT_FOUND"},
        )
    # 2. 封禁拦截（旧 token 立即失效，不等过期）
    if account["banned"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "账号已被管理员封禁，无法访问", "code": "ACCOUNT_BANNED"},
        )
    # 3. 挂能力矩阵：下游所有权限判定只认 account["capabilities"]
    account["capabilities"] = compute_capabilities(account)
    return account


# ============ 第3层：角色 / 能力判定 ============
def require_role(role: str):
    """依赖工厂：要求当前账号为指定角色。返回一个 FastAPI 依赖。"""
    async def _check(account: dict = Depends(get_current_account)) -> dict:
        if account["role"] != role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": f"权限不足：该资源需要 {role} 角色", "code": "FORBIDDEN"},
            )
        return account
    return _check


def require_capability(capability: str, message: str | None = None):
    """依赖工厂：要求当前账号具备某项能力。返回一个 FastAPI 依赖。"""
    async def _check(account: dict = Depends(get_current_account)) -> dict:
        if not account["capabilities"].get(capability):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": message or "权限不足：当前账号无该操作权限",
                    "code": "FORBIDDEN",
                },
            )
        return account
    return _check
