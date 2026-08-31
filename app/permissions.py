"""
RBAC 能力矩阵 —— 权限判定的单一真实来源。

铁律（服务端强制）：
1. 管理类能力（授权资源B / 封禁 / 删除用户）严格且仅 admin 角色持有。
2. 非 admin 即使被授权访问资源 B，也只有「只读」权限。
3. 能力永远由服务端依据数据库最新用户记录推导，绝不信任 JWT 快照。
4. resource_b_access 只影响「看得见」，永不影响「改得动」。
"""


def is_admin(user) -> bool:
    """是否是 admin 角色（唯一的管理身份判定入口）。user 可能为 None。"""
    return bool(user) and user.get("role") == "admin"


def has_resource_b_grant(user) -> bool:
    """是否被显式授权查看资源 B（仅对非 admin 有意义）。user 可能为 None。"""
    return bool(user) and bool(user.get("resource_b_access"))


def compute_capabilities(user) -> dict:
    """依据用户记录推导 6 个布尔能力。"""
    admin = is_admin(user)
    granted = has_resource_b_grant(user)
    # 注意：返回键名用驼峰（对外契约，对齐前端 app.js），
    # 内部字段（user["resource_b_access"] 等）仍是蛇形。
    return {
        # 可见性：admin 天然可见；非 admin 需被显式授权
        "viewResourceB": admin or granted,
        # 以下管理能力严格仅 admin —— 非 admin 恒为 False，不受授权字段影响
        "manageUsers": admin,
        "grantResourceB": admin,
        "banUser": admin,
        "deleteUser": admin,
        # 只读标记：被授权但非 admin 的用户处于只读模式
        "readOnlyResourceB": (not admin) and granted,
    }


def resource_b_access_mode(user) -> str:
    """返回资源 B 访问模式：'admin' / 'readonly' / 'none'。"""
    if is_admin(user):
        return "admin"
    return "readonly" if has_resource_b_grant(user) else "none"