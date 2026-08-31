"""端到端集成测试：注册→登录→访问资源→错误结构（冒烟测试）。

与 test_permissions.py 分工：那个聚焦「权限边界」，这个验证「整个系统端到端跑得通」。
LLM 走 skipped（不 mock），因为 LLM 拒绝路径已由 test_moderation.py 覆盖。
"""

import pytest
from fastapi.testclient import TestClient

from app import db
from app.main import app


@pytest.fixture
def client(tmp_path, monkeypatch):
    """TestClient + 独立临时库。"""
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()
    return TestClient(app)


def _register(c, username, password="Passw0rd!"):
    return c.post("/api/register", json={"username": username, "password": password, "nickname": "测试昵称"})


def _login(c, username, password="Passw0rd!"):
    return c.post("/api/login", json={"username": username, "password": password})


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


# ============ 注册 / 登录 ============

def test_注册_返回_201_含_user_和_moderation(client):
    reg = _register(client, "newuser")
    assert reg.status_code == 201
    body = reg.json()
    assert body["user"]["username"] == "newuser"
    assert body["user"]["role"] == "user"
    assert "moderation" in body


def test_登录_返回_token_user_expiresIn(client):
    _register(client, "loginuser")
    login = _login(client, "loginuser")
    assert login.status_code == 200
    body = login.json()
    assert body["token"]
    assert body["user"]["username"] == "loginuser"
    assert body["expiresIn"] == 43200


def test_登录_错误密码_401(client):
    _register(client, "wrongpw")
    r = _login(client, "wrongpw", "WrongPass")
    assert r.status_code == 401
    assert r.json()["code"] == "AUTH_FAILED"


# ============ 资源访问 ============

def test_资源A_返回公告板(client):
    _register(client, "auser")
    token = _login(client, "auser").json()["token"]
    r = client.get("/api/resource/a", headers=_auth(token))
    assert r.status_code == 200
    assert r.json()["resource"] == "A"
    assert isinstance(r.json()["announcements"], list)


def test_me_返回当前用户(client):
    _register(client, "meuser")
    token = _login(client, "meuser").json()["token"]
    r = client.get("/api/me", headers=_auth(token))
    assert r.status_code == 200
    assert r.json()["user"]["username"] == "meuser"


# ============ 错误结构统一（{error, code} 而非 {detail}） ============

def test_错误结构_无token_401_带code(client):
    r = client.get("/api/me")
    assert r.status_code == 401
    assert r.json()["code"] == "UNAUTHORIZED"
    assert "error" in r.json()


def test_错误结构_密码太短_422_带code(client):
    r = client.post("/api/register", json={"username": "shortpw", "password": "123"})
    assert r.status_code == 422
    assert r.json()["code"] == "INVALID_INPUT"


def test_错误结构_重复注册_400_带code(client):
    _register(client, "dupuser")
    r = _register(client, "dupuser")
    assert r.status_code == 400
    assert r.json()["code"] == "USERNAME_TAKEN"


# ============ 静态首页 ============

def test_静态首页_返回HTML(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "html" in r.text.lower()


# ============ 完整权限流（端到端） ============

def test_完整权限流_注册登录授权访问(client):
    admin_token = _login(client, "admin", "Admin@2026!").json()["token"]

    _register(client, "flowuser")
    token = _login(client, "flowuser").json()["token"]
    uid = client.get("/api/me", headers=_auth(token)).json()["user"]["id"]

    # 未授权访问 B → 403
    assert client.get("/api/resource/b", headers=_auth(token)).status_code == 403

    # admin 授权
    grant = client.patch(f"/api/admin/users/{uid}/access", json={"granted": True}, headers=_auth(admin_token))
    assert grant.status_code == 200

    # 授权后 → 200 只读
    b = client.get("/api/resource/b", headers=_auth(token))
    assert b.status_code == 200
    assert b.json()["access"]["mode"] == "readonly"
