"""permissions 模块测试：能力矩阵单元 + 权限边界集成。

聚焦两条权限边界：
  ① 回库读最新（撤销/封禁/删除立即生效，不等 token 过期）
  ② 可见 ≠ 可改（被授权用户能看资源 B，但管理能力永远是 False）
"""

import pytest
from fastapi.testclient import TestClient

from app import db
from app import store
from app.main import app
from app.permissions import compute_capabilities, resource_b_access_mode


# ============ fixtures ============

@pytest.fixture
def test_db(tmp_path, monkeypatch):
    """单元测试：独立临时库。"""
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()
    return db


@pytest.fixture
def client(tmp_path, monkeypatch):
    """集成测试：TestClient + 独立临时库。"""
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "test.db")
    db.init_db()
    return TestClient(app)


# ============ 辅助函数 ============

def _register_and_login(c, username, password="Passw0rd!"):
    c.post("/api/register", json={"username": username, "password": password, "nickname": "默认昵称"})
    login = c.post("/api/login", json={"username": username, "password": password})
    return login.json()["token"]


def _admin_token(c):
    login = c.post("/api/login", json={"username": "admin", "password": "Admin@2026!"})
    assert login.status_code == 200
    return login.json()["token"]


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


# ============ 单元：能力矩阵（可见≠可改） ============

def test_compute_capabilities_admin_全能力非只读():
    caps = compute_capabilities({"role": "admin", "resource_b_access": False})
    assert caps["viewResourceB"] is True
    assert caps["manageUsers"] is True
    assert caps["grantResourceB"] is True
    assert caps["banUser"] is True
    assert caps["deleteUser"] is True
    assert caps["readOnlyResourceB"] is False


def test_compute_capabilities_普通用户全无():
    caps = compute_capabilities({"role": "user", "resource_b_access": False})
    assert caps["viewResourceB"] is False
    assert caps["manageUsers"] is False
    assert caps["grantResourceB"] is False
    assert caps["banUser"] is False
    assert caps["deleteUser"] is False
    assert caps["readOnlyResourceB"] is False


def test_compute_capabilities_被授权用户可见但只读():
    caps = compute_capabilities({"role": "user", "resource_b_access": True})
    assert caps["viewResourceB"] is True      # 能看
    assert caps["readOnlyResourceB"] is True  # 但只读
    assert caps["manageUsers"] is False       # 绝无管理能力
    assert caps["grantResourceB"] is False
    assert caps["banUser"] is False
    assert caps["deleteUser"] is False


def test_resource_b_access_mode_三态():
    assert resource_b_access_mode({"role": "admin"}) == "admin"
    assert resource_b_access_mode({"role": "user", "resource_b_access": True}) == "readonly"
    assert resource_b_access_mode({"role": "user", "resource_b_access": False}) == "none"


# ============ 单元：store 层防护（admin 目标 / 不存在） ============

def test_resolve_manage_target_对_admin_拒绝(test_db):
    admin = store.find_by_username("admin")
    r = store.resolve_manage_target(admin["id"])
    assert r["ok"] is False
    assert r["code"] == "TARGET_IS_ADMIN"


def test_resolve_manage_target_不存在_返回_USER_NOT_FOUND(test_db):
    r = store.resolve_manage_target("no-such-id")
    assert r["ok"] is False
    assert r["code"] == "USER_NOT_FOUND"


def test_管理写操作对_admin_目标全部拒绝(test_db):
    admin = store.find_by_username("admin")
    assert store.set_banned(admin["id"], True)["code"] == "TARGET_IS_ADMIN"
    assert store.set_resource_b_access(admin["id"], True)["code"] == "TARGET_IS_ADMIN"
    assert store.remove_user(admin["id"])["code"] == "TARGET_IS_ADMIN"


# ============ 集成：角色隔离 ============

def test_admin_可读用户清单_被授权用户_403(client):
    admin_token = _admin_token(client)
    r = client.get("/api/admin/users", headers=_auth(admin_token))
    assert r.status_code == 200
    assert isinstance(r.json()["users"], list)

    # 注册普通用户并授权资源 B
    viewer_token = _register_and_login(client, "viewer")
    viewer_id = client.get("/api/me", headers=_auth(viewer_token)).json()["user"]["id"]
    grant = client.patch(f"/api/admin/users/{viewer_id}/access", json={"granted": True}, headers=_auth(admin_token))
    assert grant.status_code == 200

    # 该用户能看资源 B
    assert client.get("/api/resource/b", headers=_auth(viewer_token)).status_code == 200

    # 但访问管理端点 403
    r = client.get("/api/admin/users", headers=_auth(viewer_token))
    assert r.status_code == 403
    assert r.json()["code"] == "FORBIDDEN"


def test_只读用户_资源B可见但写操作全部403(client):
    admin_token = _admin_token(client)
    viewer_token = _register_and_login(client, "readonlyuser")
    me = client.get("/api/me", headers=_auth(viewer_token)).json()["user"]
    viewer_id = me["id"]

    grant = client.patch(f"/api/admin/users/{viewer_id}/access", json={"granted": True}, headers=_auth(admin_token))
    assert grant.status_code == 200

    # 资源 B 可见且只读
    b = client.get("/api/resource/b", headers=_auth(viewer_token))
    assert b.status_code == 200
    assert b.json()["access"]["mode"] == "readonly"
    assert b.json()["access"]["readOnly"] is True

    # 造一个受害者
    victim_token = _register_and_login(client, "victim01")
    victim_me = client.get("/api/me", headers=_auth(victim_token)).json()["user"]
    victim_id = victim_me["id"]

    # 只读用户尝试写操作 → 全部 403
    assert client.patch(f"/api/admin/users/{victim_id}/access", json={"granted": True}, headers=_auth(viewer_token)).status_code == 403
    assert client.patch(f"/api/admin/users/{victim_id}/ban", json={"banned": True}, headers=_auth(viewer_token)).status_code == 403
    assert client.delete(f"/api/admin/users/{victim_id}", headers=_auth(viewer_token)).status_code == 403
    assert client.get("/api/admin/users", headers=_auth(viewer_token)).status_code == 403


# ============ 集成：即时生效（回库读最新） ============

def test_撤销授权_立即生效(client):
    admin_token = _admin_token(client)
    token = _register_and_login(client, "revokee")
    me = client.get("/api/me", headers=_auth(token)).json()["user"]
    uid = me["id"]

    client.patch(f"/api/admin/users/{uid}/access", json={"granted": True}, headers=_auth(admin_token))
    assert client.get("/api/resource/b", headers=_auth(token)).status_code == 200

    client.patch(f"/api/admin/users/{uid}/access", json={"granted": False}, headers=_auth(admin_token))
    # 同一 token 立即 403，无需重新登录
    after = client.get("/api/resource/b", headers=_auth(token))
    assert after.status_code == 403
    assert after.json()["code"] == "FORBIDDEN"


def test_封禁_立即生效_旧token失效(client):
    admin_token = _admin_token(client)
    token = _register_and_login(client, "bannee")
    me = client.get("/api/me", headers=_auth(token)).json()["user"]
    uid = me["id"]

    client.patch(f"/api/admin/users/{uid}/ban", json={"banned": True}, headers=_auth(admin_token))

    # 旧 token 立即失效
    r = client.get("/api/me", headers=_auth(token))
    assert r.status_code == 403
    assert r.json()["code"] == "ACCOUNT_BANNED"

    # 重新登录也被拒
    relogin = client.post("/api/login", json={"username": "bannee", "password": "Passw0rd!"})
    assert relogin.status_code == 403
    assert relogin.json()["code"] == "ACCOUNT_BANNED"


def test_删除_立即生效_旧token返回_ACCOUNT_NOT_FOUND(client):
    admin_token = _admin_token(client)
    token = _register_and_login(client, "deletee")
    me = client.get("/api/me", headers=_auth(token)).json()["user"]
    uid = me["id"]

    r = client.delete(f"/api/admin/users/{uid}", headers=_auth(admin_token))
    assert r.status_code == 200

    after = client.get("/api/me", headers=_auth(token))
    assert after.status_code == 401
    assert after.json()["code"] == "ACCOUNT_NOT_FOUND"


# ============ 集成：admin 保护 + 边界 ============

def test_管理员不能对自己操作(client):
    admin_token = _admin_token(client)
    me = client.get("/api/me", headers=_auth(admin_token)).json()["user"]
    admin_id = me["id"]

    r = client.patch(f"/api/admin/users/{admin_id}/ban", json={"banned": True}, headers=_auth(admin_token))
    assert r.status_code == 400
    assert r.json()["code"] == "CANNOT_TARGET_SELF"


def test_边界_granted非布尔_400(client):
    admin_token = _admin_token(client)
    token = _register_and_login(client, "boundary")
    me = client.get("/api/me", headers=_auth(token)).json()["user"]
    uid = me["id"]

    r = client.patch(f"/api/admin/users/{uid}/access", json={"granted": "yes"}, headers=_auth(admin_token))
    assert r.status_code == 422  # Pydantic 拦截非布尔


def test_边界_操作不存在用户_404(client):
    admin_token = _admin_token(client)
    r = client.delete("/api/admin/users/nope", headers=_auth(admin_token))
    assert r.status_code == 404
    assert r.json()["code"] == "USER_NOT_FOUND"


def test_未登录访问管理端点_401(client):
    assert client.get("/api/admin/users").status_code == 401
