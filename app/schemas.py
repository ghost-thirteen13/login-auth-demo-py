"""
Pydantic 请求/响应模型 —— 入参的第一道「类型 + 长度」校验。

职责边界（和 store.py 校验的分工）：
  - 这里只拦「类型不对 / 长度不够」这类结构问题（密码 < 6 位等）
  - store.validate_username 拦「业务规则」：3-20 位 ASCII、保留名黑名单
  两层不重复：schemas 管「形状」，store 管「规则」。

Pydantic 校验失败会自动抛 422（RequestValidationError），由 FastAPI 统一返回。
注意：422 的默认响应结构是 Pydantic 英文格式，阶段 5 会统一拍平成 {error, code}。
"""

from typing import Optional

from pydantic import BaseModel, Field, StrictBool


class RegisterRequest(BaseModel):
    username: str
    password: str = Field(min_length=6)
    nickname: Optional[str] = None


class LoginRequest(BaseModel):
    username: str
    password: str


class GrantAccessRequest(BaseModel):
    granted: StrictBool


class BanRequest(BaseModel):
    banned: StrictBool
