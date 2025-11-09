from datetime import datetime, timedelta, timezone

from app.core.config import settings
from jose import jwt
from passlib.context import CryptContext

# 1. Khởi tạo bối cảnh Passlib (giống hệt user-service)
#    Dùng để so sánh mật khẩu thô với mật khẩu đã băm
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Kiểm tra mật khẩu thô có khớp với mật khẩu đã băm không"""
    return pwd_context.verify(plain_password, hashed_password)


# 2. Các hàm tạo JWT Token


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Tạo Access Token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        # Nếu không có delta, mặc định là 30 phút (từ config)
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )

    to_encode.update({"exp": expire})

    # Mã hóa token
    encoded_jwt = jwt.encode(
        to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
    )
    return encoded_jwt


def create_refresh_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Tạo Refresh Token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        # Mặc định là 7 ngày (từ config)
        expire = datetime.now(timezone.utc) + timedelta(
            days=settings.REFRESH_TOKEN_EXPIRE_DAYS
        )

    to_encode.update({"exp": expire})

    # Mã hóa token
    encoded_jwt = jwt.encode(
        to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
    )
    return encoded_jwt
