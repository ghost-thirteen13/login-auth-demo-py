"""
认证路由：注册 + 登录。

这两个端点是公开的（不需要登录），所以不挂鉴权依赖。
"""

from fastapi import APIRouter, HTTPException, status

from app import moderation
from app import store
from app.auth import create_token, hash_password, verify_password
from app.schemas import LoginRequest, RegisterRequest

router = APIRouter(prefix="/api", tags=["auth"])

# 登录时用户不存在也执行一次假 bcrypt 比较，抹平时序侧信道（防账号枚举，见 app.js [安全 F-7]）
_DUMMY_HASH = hash_password("timing-safe-dummy-password")


@router.post("/register", status_code=201)
async def register(body: RegisterRequest):
    """注册：6 步流水线。

    顺序有讲究：
      校验(1) → 查重(2) → 昵称(3) → LLM审核(4/5) → 落库(6)
      - 查重放在 LLM 之前：先拦掉重复名，省 LLM token
      - LLM 放在落库之前：审核不过，数据根本不进库
      - 密码长度已在 schemas.Field(min_length=6) 拦（422），这里不重复
    """
    # 1. 用户名校验（格式 3-20 ASCII + 保留名）
    ok, code, msg = store.validate_username(body.username)
    if not ok:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"error": msg, "code": code})

    # 2. 查重（先于 LLM，省 token）
    if store.find_by_username(body.username):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail={"error": "用户名已存在", "code": "USERNAME_TAKEN"},
        )

    # 3. 昵称校验（None 允许；空串/纯空白拒绝；规则层敏感词拒绝）
    ok, code, msg = store.validate_nickname(body.nickname)
    if not ok:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"error": msg, "code": code})

    # 4. 用户名 LLM 审核（只审核，不参与权限）
    username_mod = await moderation.check_username(body.username)
    if username_mod["verdict"] == "deny":
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail={
                "error": f"用户名包含违规内容：{username_mod['reason']}",
                "code": "USERNAME_VIOLATION",
                "category": username_mod.get("category"),
            },
        )

    # 5. 昵称 LLM 审核（有昵称才审；空昵称跳过）
    nickname_mod = None
    if body.nickname and body.nickname.strip():
        nickname_mod = await moderation.check_nickname(body.nickname.strip())
        if nickname_mod["verdict"] == "deny":
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": f"昵称包含违规内容：{nickname_mod['reason']}",
                    "code": "NICKNAME_VIOLATION",
                    "category": nickname_mod.get("category"),
                },
            )

    # 6. 落库：pending_review = 任一审核待复审
    pending_review = bool(
        username_mod.get("pending_review")
        or (nickname_mod and nickname_mod.get("pending_review"))
    )
    # moderation 摘要（扁平结构，待复审面板据此显示 reason）
    if pending_review:
        mod_summary = {
            "verdict": "allow_pending",
            "category": None,
            "reason": "用户名或昵称待人工复审（LLM 未完成审核）",
            "source": "fallback",
        }
    else:
        llm_used = username_mod.get("source") == "llm" or (nickname_mod and nickname_mod.get("source") == "llm")
        mod_summary = {
            "verdict": "allow",
            "category": None,
            "reason": "审核通过",
            "source": "llm" if llm_used else "rule",
        }

    try:
        user = store.create_user(
            body.username, body.password, body.nickname,
            pending_review=pending_review,
            moderation=mod_summary,
        )
    except store.DuplicateUsernameError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"error": str(e), "code": e.code})
    except store.ReservedNameError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"error": str(e), "code": e.code})

    return {
        "message": "注册成功",
        "user": user,
        "moderation": mod_summary,
    }


@router.post("/login")
async def login(body: LoginRequest):
    """登录：查用户 → 校验密码 → 查封禁 → 签发 JWT。

    关键点：
      - 用户不存在也做一次假 bcrypt（_DUMMY_HASH），抹平时序差
      - 封禁判断放在密码校验【之后】，避免暴露「账号是否存在/被封」给账号枚举攻击
    """
    user = store.find_by_username(body.username)

    # 用户不存在：假比较抹平时序，再统一报「用户名或密码错误」
    if user is None:
        verify_password(body.password, _DUMMY_HASH)
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail={"error": "用户名或密码错误", "code": "AUTH_FAILED"},
        )

    # 密码错误
    if not verify_password(body.password, user["password_hash"]):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail={"error": "用户名或密码错误", "code": "AUTH_FAILED"},
        )

    # 封禁拦截（置于密码校验之后）
    if user["banned"]:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail={"error": "账号已被管理员封禁，无法登录", "code": "ACCOUNT_BANNED"},
        )

    token = create_token({"id": user["id"], "username": user["username"], "role": user["role"]})
    return {
        "token": token,
        "user": store.public_view(user),
        "expiresIn": 43200,
    }
