from datetime import timedelta

import httpx  # Thư viện để gọi API (user-service)
import redis
from app.core.config import settings
from app.core.security import (create_access_token, create_refresh_token,
                               verify_password)
from app.models.token import Token
from fastapi import HTTPException, status

# --- HÀM LƯU VÀO REDIS ---


def save_refresh_token_to_redis(db: redis.Redis, refresh_token: str, user_email: str):
    """
    Lưu Refresh Token vào Redis với thời gian hết hạn
    Chúng ta dùng 'refresh_token' làm key
    """
    db.set(
        refresh_token, user_email, ex=timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )


# --- HÀM LOGIC CHÍNH ---


async def authenticate_user(email: str, password: str, db_redis: redis.Redis) -> Token:
    """
    Hàm logic chính để xác thực người dùng và tạo token
    """

    # --- Bước 1: Gọi User-Service để lấy thông tin user ---
    # (Đây là giao tiếp service-to-service)

    # Chúng ta cần một API mới bên user-service: /api/users/by-email/{email}
    # (Chúng ta sẽ thêm API này vào user-service ở bước sau)

    user_data = None
    try:
        # httpx là thư viện gọi API bất đồng bộ
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{settings.USER_SERVICE_URL}/users/by-email/{email}"
            )

        if response.status_code == 200:
            user_data = response.json()
        elif response.status_code == 404:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Email không tồn tại",
            )
        else:
            # Nếu user-service bị lỗi, chúng ta cũng báo lỗi
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="User service không phản hồi.",
            )

    except httpx.RequestError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Không thể kết nối đến User service.",
        )

    # --- Bước 2: Kiểm tra mật khẩu ---
    hashed_password = user_data.get("hashed_password")

    if not verify_password(password, hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sai mật khẩu",
        )

    # --- Bước 3: Tạo Access Token và Refresh Token ---
    # Dữ liệu payload cho token (chúng ta dùng email làm 'subject')
    token_payload = {"sub": user_data.get("email")}

    access_token = create_access_token(data=token_payload)
    refresh_token = create_refresh_token(data=token_payload)

    # --- Bước 4: Lưu Refresh Token vào Redis ---
    save_refresh_token_to_redis(db_redis, refresh_token, user_data.get("email"))

    return Token(access_token=access_token, refresh_token=refresh_token)
