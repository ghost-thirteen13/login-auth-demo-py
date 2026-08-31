"""
数据层：SQLite 连接 + 建表 + seed admin。

职责边界（本模块只做三件事，不碰业务逻辑）：
1. get_connection() —— 打开并返回 SQLite 连接（带 row_factory，按列名取值）
2. init_db()       —— 建 users 表（幂等）+ seed 一个 admin 账号（幂等）
业务层的查重/创建/授权/封禁等，在 store.py 里实现。

注意：本模块是最底层，被 store.py 依赖；因此不能反向 import auth.py
（否则会形成 db -> auth -> store -> db 的循环依赖），
seed 里需要 bcrypt 哈希时直接 import bcrypt。
"""

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import bcrypt

# 数据库文件路径：项目根目录下的 data/users.db
DB_PATH = Path(__file__).resolve().parent.parent / "data" / "users.db"


def get_connection() -> sqlite3.Connection:
    """打开并返回一个 SQLite 连接。"""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """建库建表 + seed admin（幂等，可重复调用）。"""
    conn = get_connection()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id                TEXT PRIMARY KEY,
                username          TEXT NOT NULL UNIQUE,
                normalized        TEXT NOT NULL UNIQUE,
                password_hash     TEXT NOT NULL,
                nickname          TEXT,
                role              TEXT NOT NULL DEFAULT 'user',
                resource_b_access INTEGER NOT NULL DEFAULT 0,
                banned            INTEGER NOT NULL DEFAULT 0,
                pending_review    INTEGER NOT NULL DEFAULT 0,
                moderation        TEXT,
                created_at        TEXT NOT NULL
            )
            """
        )

        # 列迁移：旧库（无 moderation 列）补列，幂等
        cols = [r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()]
        if 'moderation' not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN moderation TEXT")

        # seed admin：先查，不存在才插（幂等）
        row = conn.execute(
            "SELECT 1 FROM users WHERE normalized = ?", ("admin",)
        ).fetchone()
        if row is None:
            admin_pwd = os.environ.get("ADMIN_SEED_PASSWORD", "Admin@2026!")
            conn.execute(
                """
                INSERT INTO users
                    (id, username, normalized, password_hash, nickname,
                     role, resource_b_access, banned, pending_review, moderation, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid4()),
                    "admin",
                    "admin",
                    bcrypt.hashpw(admin_pwd.encode("utf-8"), bcrypt.gensalt()).decode("utf-8"),
                    None,
                    "admin",
                    True,
                    False,
                    False,
                    json.dumps({'verdict': 'allow', 'category': None, 'reason': 'seed 账号', 'source': 'seed'}, ensure_ascii=False),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

        conn.commit()
    finally:
        conn.close()
