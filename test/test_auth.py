"""auth 模块单元测试：bcrypt 哈希 + JWT 签发/验签。"""

import pytest
import jwt

from app.auth import create_token, decode_token, hash_password, verify_password


def test_hash_password_returns_bcrypt_hash_without_plaintext():
    h = hash_password("Secret123!")
    assert h.startswith("$2")          # bcrypt 格式哈希
    assert "Secret123!" not in h       # 不含明文

# 测试密码样本
VALID_PASSWORD = "Secret123!"
WRONG_PASSWORD = "Wrong"

def test_verify_correct_password():
    """验证正确密码应返回 True"""
    hashed = hash_password(VALID_PASSWORD)
    assert verify_password(VALID_PASSWORD, hashed) is True

def test_verify_wrong_password():
    """验证错误密码应返回 False"""
    hashed = hash_password(VALID_PASSWORD)
    assert verify_password(WRONG_PASSWORD, hashed) is False

def test_verify_multiple_hashes_same_password():
    """多次哈希同一密码，每次结果不同，但验证均应通过"""
    for _ in range(3):
        hashed = hash_password(VALID_PASSWORD)
        assert verify_password(VALID_PASSWORD, hashed) is True

def test_verify_empty_password():
    """空密码的哈希和验证"""
    empty_hash = hash_password("")
    assert verify_password("", empty_hash) is True
    assert verify_password(" ", empty_hash) is False  # 空格不等同于空

def test_verify_special_characters():
    """测试包含特殊字符的密码"""
    special = "P@ssw0rd!#$%^&*()"
    h = hash_password(special)
    assert verify_password(special, h) is True

def test_verify_long_password_within_72_bytes():
    """72 字节以内的长密码能正常哈希验证（bcrypt 有 72 字节上限）。"""
    long_pw = "a" * 60
    h = hash_password(long_pw)
    assert verify_password(long_pw, h) is True


def test_hash_password_rejects_over_72_bytes():
    """bcrypt 限制：密码超过 72 字节会抛 ValueError。"""
    with pytest.raises(ValueError):
        hash_password("a" * 73)

def test_verify_invalid_hash_raises():
    """无效哈希（非法 salt 格式）让 bcrypt.checkpw 抛 ValueError，而非返回 False。"""
    with pytest.raises(ValueError):
        verify_password(VALID_PASSWORD, "invalid_hash")


# ============ JWT 签发 / 验签 ============

def test_create_token_and_decode_roundtrip_carries_claims():
    token = create_token({"id": "u1", "username": "alice", "role": "user"})
    payload = decode_token(token)
    assert payload["id"] == "u1"
    assert payload["username"] == "alice"
    assert payload["role"] == "user"


def test_decode_token_rejects_tampered_token():
    token = create_token({"id": "u1", "username": "alice", "role": "user"})
    # 篡改「签名段首字符」而非末位：base64url 末位字符的低 2 bit 是 padding 位，
    # 若恰好改到 padding 位，签名字节不变、验签仍通过，测试会 flaky。
    # 首字符必然编码有效字节，改它一定能让验签失败。
    header, payload, sig = token.split(".")
    sig = ("A" if sig[0] != "A" else "B") + sig[1:]
    tampered = ".".join([header, payload, sig])
    with pytest.raises(jwt.PyJWTError):
        decode_token(tampered)


def test_decode_token_rejects_wrong_secret():
    # 用错误密钥手动签一个 token；decode_token 用 config 密钥验签，应失败
    bad = jwt.encode({"id": "u1", "username": "alice", "role": "user"}, "x" * 32, algorithm="HS256")
    with pytest.raises(jwt.PyJWTError):
        decode_token(bad)


def test_create_token_does_not_add_nickname():
    payload = decode_token(create_token({"id": "u1", "username": "alice", "role": "user"}))
    assert "nickname" not in payload
