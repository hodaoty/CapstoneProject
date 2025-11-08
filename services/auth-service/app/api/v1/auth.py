import redis
from app.db.database import get_redis_db
from app.models.token import Token
from app.services import auth_service
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

router = APIRouter()


@router.post("/auth/login", response_model=Token)
async def login_for_access_token(
    db: redis.Redis = Depends(get_redis_db),
    form_data: OAuth2PasswordRequestForm = Depends(),
):
    """
    API đăng nhập.

    Chúng ta dùng OAuth2PasswordRequestForm của FastAPI,
    nó sẽ tự động lấy 'username' (chính là email) và 'password'
    từ một form-data request.
    """

    # Gọi hàm logic chính từ service mà chúng ta đã viết
    try:
        token_data = await auth_service.authenticate_user(
            email=form_data.username, password=form_data.password, db_redis=db
        )
        return token_data

    except HTTPException as e:
        # Bắt lại lỗi (ví dụ: Sai email, sai pass) và trả về
        raise e
    except Exception as e:
        # Bắt các lỗi chung khác
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Lỗi máy chủ nội bộ: {str(e)}",
        )
