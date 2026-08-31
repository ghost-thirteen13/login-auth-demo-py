"""
存储层：用户数据的增删改查 + 业务校验。

本模块用 SQLite 替代 JSON 文件存储。
db.py 只管「连接 + 建表 + seed」，这里的业务逻辑全部用 SQL 实现。

安全规则（服务端强制，与 LLM 无关）：
1. 用户名全局唯一（归一化后大小写不敏感），严格限制 [a-zA-Z0-9_]，3-20 位
2. 保留名黑名单：禁止注册权限相关名称
3. create_user 强制 role='user'，忽略调用方传入的任何角色
4. resource_b_access 与 banned 只能由 admin 通过管理端点变更，注册一律初始化为 False
5. 管理类写操作（授权/封禁/删除）再次拒绝以 admin 为目标（TARGET_IS_ADMIN）
"""

import json
import re
from datetime import datetime, timezone
from uuid import uuid4

import bcrypt

from app.db import get_connection
from app.moderation import check_rule_layer
from app.permissions import compute_capabilities

# 权限相关保留名（小写），注册不可用
RESERVED_NAMES = [
    'admin', 'administrator', 'system', 'root', 'superuser', 'moderator',
    'official', 'support', 'staff', 'operator', 'webmaster', 'owner',
    '管理员', '系统', '官方', '客服', '版主', '版务', '坛主', '站长',
]


class DuplicateUsernameError(Exception):
    """用户名已存在。"""
    def __init__(self, username):
        super().__init__(f'用户名已存在: {username}')
        self.code = 'USERNAME_TAKEN'


class ReservedNameError(Exception):
    """用户名为系统保留名，禁止注册。"""
    def __init__(self, username):
        super().__init__(f'用户名为系统保留名，禁止注册: {username}')
        self.code = 'USERNAME_RESERVED'


def normalize_username(name) -> str:
    """用户名归一化：全角→半角、转小写、去首尾空白、压缩连续空格。"""
    s = str(name or '')
    # 全角空格 U+3000 → 半角空格
    s = s.replace('\u3000', ' ')
    # 全角 ASCII（U+FF01–U+FF5E）→ 半角：码点减 0xFEE0
    s = ''.join(
        chr(ord(ch) - 0xFEE0) if '\uFF01' <= ch <= '\uFF5E' else ch
        for ch in s
    )
    s = s.strip().lower()
    s = ' '.join(s.split())  # 压缩连续空格为单个
    return s


def is_reserved_name(name) -> bool:
    """是否命中权限相关保留名。"""
    return normalize_username(name) in RESERVED_NAMES


def validate_username(username):
    """用户名服务端校验：3-20 位，仅 [a-zA-Z0-9_]，且非保留名。
    返回三元组 (ok, code, message)。"""
    if not isinstance(username, str):
        return False, 'INVALID_INPUT', '用户名必须为字符串'
    trimmed = username.strip()
    # 字符集校验优先于长度校验：让「张三」明确报 USERNAME_INVALID_CHAR，而非误判长度不足
    if not re.fullmatch(r'[a-zA-Z0-9_]+', trimmed):
        return False, 'USERNAME_INVALID_CHAR', '用户名只能包含字母、数字和下划线（3-20 位）'
    if len(trimmed) < 3:
        return False, 'USERNAME_TOO_SHORT', '用户名长度至少为 3 个字符'
    if len(trimmed) > 20:
        return False, 'USERNAME_TOO_LONG', '用户名长度不能超过 20 个字符'
    if is_reserved_name(trimmed):
        return False, 'USERNAME_RESERVED', '该用户名为系统保留名，禁止注册'
    return True, None, None


def validate_nickname(nickname):
    """昵称校验：None 允许；空串/纯空白拒绝；>20 拒绝。
    规则层敏感词检测等 moderation.py 写完再接入（见 TODO）。"""
    # 显式 None → 允许（不识别为空昵称，不触发 LLM）
    if nickname is None:
        return True, None, None
    trimmed = str(nickname).strip()
    if not trimmed:
        return False, 'NICKNAME_REQUIRED', '昵称不能为空，请填写昵称'
    if len(trimmed) > 20:
        return False, 'NICKNAME_TOO_LONG', '昵称长度不能超过 20 个字符'
    # 规则层敏感词检测（复用 moderation 的 check_rule_layer，与用户名审核同源）
    rule_hit = check_rule_layer(trimmed)
    if rule_hit:
        return False, 'NICKNAME_VIOLATION', f'昵称包含不当内容（命中敏感词：{rule_hit["word"]}），请更换后重试'
    return True, None, None

# ============ 对外投影 ============

def _parse_moderation(raw) -> dict:
    """把 moderation 列的 JSON 字符串解析成 dict；空/无效返回默认值。"""
    if not raw:
        return {'verdict': 'allow', 'category': None, 'reason': None, 'source': 'none'}
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {'verdict': 'allow', 'category': None, 'reason': None, 'source': 'none'}


def public_view(user: dict) -> dict:
    """对外投影：绝不包含 password_hash。capabilities 为服务端推导。
    字段名用驼峰（对齐前端 app.js 契约），内部存储仍是蛇形。"""
    return {
        'id': user['id'],
        'username': user['username'],
        'nickname': user.get('nickname'),
        'role': user['role'],
        'resourceBAccess': bool(user.get('resource_b_access')),
        'banned': bool(user.get('banned')),
        'pendingReview': bool(user.get('pending_review')),
        'moderation': _parse_moderation(user.get('moderation')),
        'createdAt': user['created_at'],
        'capabilities': compute_capabilities(user),
    }


# ============ 查询类 ============

def find_by_username(username: str):
    """按用户名查用户（大小写不敏感，走 normalized 列）。返回 dict 或 None。"""
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM users WHERE normalized = ?",
            (normalize_username(username),),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def find_by_id(user_id: str):
    """按 id 精确查找（返回内部记录，供鉴权读最新角色/封禁状态）。"""
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def list_pending_review() -> list:
    """列出待人工复审的用户（对外投影）。"""
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM users WHERE pending_review = 1 ORDER BY created_at DESC"
        ).fetchall()
        return [public_view(dict(r)) for r in rows]
    finally:
        conn.close()


def list_all() -> list:
    """全量用户清单（对外投影，按注册时间倒序）。"""
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM users ORDER BY created_at DESC"
        ).fetchall()
        return [public_view(dict(r)) for r in rows]
    finally:
        conn.close()


# ============ 写入类 ============

def create_user(username: str, password: str, nickname=None, pending_review: bool = False, moderation: dict | None = None) -> dict:
    """创建用户。忽略任何角色参数，一律强制 role='user'。
    抛 DuplicateUsernameError / ReservedNameError。"""
    if is_reserved_name(username):
        raise ReservedNameError(username)
    normalized = normalize_username(username)

    conn = get_connection()
    try:
        # 查重（代码层第一道）；数据库 UNIQUE 约束是第二道兜底
        dup = conn.execute(
            "SELECT 1 FROM users WHERE normalized = ?", (normalized,)
        ).fetchone()
        if dup:
            raise DuplicateUsernameError(username)

        user_id = str(uuid4())
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        stored_nickname = (nickname.strip() or None) if isinstance(nickname, str) else None

        conn.execute(
            """
            INSERT INTO users
                (id, username, normalized, password_hash, nickname,
                 role, resource_b_access, banned, pending_review, moderation, created_at)
            VALUES (?, ?, ?, ?, ?, 'user', 0, 0, ?, ?, ?)
            """,
            (
                user_id,
                str(username).strip(),
                normalized,
                password_hash,
                stored_nickname,
                1 if pending_review else 0,
                json.dumps(moderation, ensure_ascii=False) if moderation else None,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()

        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return public_view(dict(row))
    finally:
        conn.close()


def resolve_manage_target(user_id: str):
    """管理写操作的公共前置校验：目标必须存在，且不得为 admin。
    返回 {'ok': bool, ...}。"""
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            return {'ok': False, 'code': 'USER_NOT_FOUND', 'message': '目标用户不存在'}
        target = dict(row)
        if target['role'] == 'admin':
            return {'ok': False, 'code': 'TARGET_IS_ADMIN',
                    'message': '不允许对 admin 账号执行该操作（管理员权限受保护）'}
        return {'ok': True, 'user': target}
    finally:
        conn.close()


def set_resource_b_access(user_id: str, granted: bool):
    """授权/撤销「资源 B 只读访问」。仅影响可见性，永不授予管理能力。"""
    found = resolve_manage_target(user_id)
    if not found['ok']:
        return found
    conn = get_connection()
    try:
        conn.execute(
            "UPDATE users SET resource_b_access = ? WHERE id = ?",
            (1 if granted else 0, user_id),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return {'ok': True, 'user': public_view(dict(row))}
    finally:
        conn.close()


def set_banned(user_id: str, banned: bool):
    """封禁/解封用户。封禁后已签发 token 立即失效（见 auth 账号中间件）。"""
    found = resolve_manage_target(user_id)
    if not found['ok']:
        return found
    conn = get_connection()
    try:
        conn.execute(
            "UPDATE users SET banned = ? WHERE id = ?",
            (1 if banned else 0, user_id),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return {'ok': True, 'user': public_view(dict(row))}
    finally:
        conn.close()


def remove_user(user_id: str):
    """删除用户（不可恢复）。admin 账号受保护，不可删除。"""
    found = resolve_manage_target(user_id)
    if not found['ok']:
        return found
    conn = get_connection()
    try:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        return {'ok': True, 'user': public_view(found['user'])}
    finally:
        conn.close()


# ============ 统计 ============

def stats() -> dict:
    """统计面板数据。"""
    conn = get_connection()
    try:
        total = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()['n']
        admin_count = conn.execute("SELECT COUNT(*) AS n FROM users WHERE role = 'admin'").fetchone()['n']
        pending_count = conn.execute("SELECT COUNT(*) AS n FROM users WHERE pending_review = 1").fetchone()['n']
        granted_count = conn.execute(
            "SELECT COUNT(*) AS n FROM users WHERE role != 'admin' AND resource_b_access = 1"
        ).fetchone()['n']
        banned_count = conn.execute("SELECT COUNT(*) AS n FROM users WHERE banned = 1").fetchone()['n']
        recent_rows = conn.execute(
            "SELECT * FROM users ORDER BY created_at DESC LIMIT 20"
        ).fetchall()
        return {
            'totalUsers': total,
            'adminCount': admin_count,
            'pendingReviewCount': pending_count,
            'grantedCount': granted_count,
            'bannedCount': banned_count,
            'recentRegistrations': [public_view(dict(r)) for r in recent_rows],
        }
    finally:
        conn.close()