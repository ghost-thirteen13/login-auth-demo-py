"""
配置层：统一读取环境变量。

规则：业务模块只从本模块取值，不直接碰 os.environ，
这样「密钥从哪来 / 默认值是什么」都收敛在一个地方。
"""

import os
import secrets
from pathlib import Path

from dotenv import load_dotenv

# 显式指向项目根目录的 .env（不依赖启动时的 cwd）
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

# 未配置 JWT_SECRET 时的兜底密钥：必须「模块级缓存」，
# 否则每次调用 secrets.token_hex 都生成新值，签发与验签用的密钥不一致，token 全部验不过。
_FALLBACK_JWT_SECRET = secrets.token_hex(32)


def get_jwt_secret() -> str:
    """JWT 签名密钥。生产必须配置 JWT_SECRET，否则重启后所有已签发 token 失效。"""
    return os.environ.get("JWT_SECRET") or _FALLBACK_JWT_SECRET


def get_llm_config() -> dict:
    """LLM 配置（OpenAI 兼容接口，默认 DeepSeek）。"""
    return {
        "api_key": os.environ.get("LLM_API_KEY", ""),
        "base_url": os.environ.get("LLM_BASE_URL", "https://api.deepseek.com"),
        "model": os.environ.get("LLM_MODEL", "deepseek-chat"),
    }


def get_admin_seed_password() -> str:
    """seed admin 的初始口令。"""
    return os.environ.get("ADMIN_SEED_PASSWORD", "Admin@2026!")
