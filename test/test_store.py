"""store 模块单元测试：归一化 / 保留名 / 用户名·昵称校验 / 创建用户。"""

import pytest

from app import db
from app import store


# ============ DB 隔离 fixture ============

@pytest.fixture
def test_db(tmp_path, monkeypatch):
    """每个测试用独立的临时数据库，不污染真实 users.db。"""
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()
    return db


# ============ 组 A：纯函数（不需要 test_db） ============

def test_normalize_username_lowercases_and_strips():
    assert store.normalize_username("  Zhang San ") == "zhang san"


def test_normalize_username_fullwidth_to_halfwidth():
    assert store.normalize_username("ＡＤＭＩＮ") == "admin"
    assert store.normalize_username("ａｄｍｉｎ") == "admin"


def test_is_reserved_name_rejects_ascii_and_variants():
    for name in ["admin", "Admin", "ADMIN", "Ａｄｍｉｎ", "administrator", "SYSTEM",
                 "system", "root", "superuser", "moderator", "official", "support",
                 "staff", "operator", "webmaster", "owner"]:
        assert store.is_reserved_name(name) is True, f"应拒绝保留名: {name}"


def test_is_reserved_name_accepts_normal_names():
    for name in ["zhangsan", "tom_2026", "hello world", "neo"]:
        assert store.is_reserved_name(name) is False, f"不应拒绝: {name}"


def test_validate_username_non_string_returns_invalid_input():
    ok, code, _ = store.validate_username(123)
    assert ok is False
    assert code == "INVALID_INPUT"


def test_validate_username_too_short():
    ok, code, _ = store.validate_username("ab")
    assert ok is False
    assert code == "USERNAME_TOO_SHORT"


def test_validate_username_too_long():
    ok, code, _ = store.validate_username("a" * 21)
    assert ok is False
    assert code == "USERNAME_TOO_LONG"


def test_validate_username_chinese_returns_invalid_char():
    ok, code, _ = store.validate_username("张三")
    assert ok is False
    assert code == "USERNAME_INVALID_CHAR"


def test_validate_username_space_returns_invalid_char():
    ok, code, _ = store.validate_username("bad name")
    assert ok is False
    assert code == "USERNAME_INVALID_CHAR"


def test_validate_username_illegal_chars_returns_invalid_char():
    ok, code, _ = store.validate_username("bad<>name")
    assert ok is False
    assert code == "USERNAME_INVALID_CHAR"


def test_validate_username_reserved_name():
    ok, code, _ = store.validate_username("admin")
    assert ok is False
    assert code == "USERNAME_RESERVED"


def test_validate_username_valid():
    ok, code, _ = store.validate_username("alice_01")
    assert ok is True
    assert code is None


def test_validate_nickname_none_allowed_empty_rejected():
    assert store.validate_nickname(None)[0] is True
    assert store.validate_nickname("")[1] == "NICKNAME_REQUIRED"
    assert store.validate_nickname("   ")[1] == "NICKNAME_REQUIRED"


def test_validate_nickname_valid():
    assert store.validate_nickname("正常昵称")[0] is True


def test_validate_nickname_sensitive_word_violation():
    ok, code, _ = store.validate_nickname("傻逼")
    assert ok is False
    assert code == "NICKNAME_VIOLATION"


def test_validate_nickname_too_long():
    ok, code, _ = store.validate_nickname("a" * 21)
    assert ok is False
    assert code == "NICKNAME_TOO_LONG"


# ============ 组 B：数据库操作（用 test_db） ============

def test_create_user_projection_hides_password_hash(test_db):
    user = store.create_user("alice", "password123", nickname="爱丽丝")
    assert user["role"] == "user"
    assert "resourceBAccess" in user
    assert "capabilities" in user
    assert "password_hash" not in user          # 严禁泄露哈希


def test_create_user_rejects_duplicate_case_insensitive(test_db):
    store.create_user("ZhangSan", "password123")
    with pytest.raises(store.DuplicateUsernameError):
        store.create_user("zhangsan", "password123")


def test_create_user_rejects_reserved_name(test_db):
    with pytest.raises(store.ReservedNameError):
        store.create_user("System", "password123")


def test_create_user_forces_role_user(test_db):
    user = store.create_user("hacker", "password123")
    assert user["role"] == "user"               # 注册永远拿不到 admin


def test_list_pending_review_and_stats(test_db):
    store.create_user("pending_guy", "password123", pending_review=True,
                      moderation={"verdict": "allow_pending", "source": "fallback"})
    pending = store.list_pending_review()
    assert len(pending) == 1
    assert pending[0]["username"] == "pending_guy"
    stats = store.stats()
    assert stats["totalUsers"] >= 2             # seed admin + pending_guy
    assert isinstance(stats["recentRegistrations"], list)
