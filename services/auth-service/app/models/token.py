from typing import Optional

from pydantic import BaseModel


class Token(BaseModel):
    """
    Schema cho dữ liệu trả về khi login thành công.
    """

    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenPayload(BaseModel):
    """
    Schema cho dữ liệu bên trong JWT Access Token.
    'sub' (subject) là tên quy ước để lưu 'user_id' hoặc 'email'.
    """

    sub: str  # Subject (Chúng ta sẽ dùng email)


class RefreshTokenPayload(BaseModel):
    """
    Schema cho dữ liệu bên trong JWT Refresh Token.
    """

    sub: str  # Subject (Chúng ta sẽ dùng email)


class TokenData(BaseModel):
    """
    Schema để chứa dữ liệu đọc được từ token (sau khi giải mã).
    """

    email: Optional[str] = None
