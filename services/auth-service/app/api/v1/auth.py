import redis
import hashlib
from jose import jwt
from app.db.database import get_redis_db
from app.models.token import Token
from app.services import auth_service
from app.core.config import settings
from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
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

@router.get("/auth/verify-internal")
def verify_internal(request: Request):
    """
    API nội bộ dùng cho Nginx auth_request.
    Luôn trả về 200 OK, nhưng sẽ inject headers băm nếu token hợp lệ để Nginx ghi log.
    """
    auth_header = request.headers.get("Authorization")
    headers = {
        "X-Token-Hash": "",
        "X-User-Id-Hash": "",
        "X-User-Role": ""
    }
    
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        try:
            # Decode token (không verify qua DB, chỉ lấy payload)
            payload = jwt.decode(
                token, 
                settings.JWT_SECRET_KEY, 
                algorithms=[settings.JWT_ALGORITHM]
            )
            user_id = payload.get("sub")
            role = payload.get("role", "USER")
            
            if user_id:
                # Băm token và email bằng SHA-256
                headers["X-Token-Hash"] = hashlib.sha256(token.encode()).hexdigest()
                headers["X-User-Id-Hash"] = hashlib.sha256(user_id.encode()).hexdigest()
                headers["X-User-Role"] = role
        except Exception:
            # Token sai hoặc hết hạn -> Cứ trả về 200 với header rỗng
            pass 
            
    return Response(content="OK", status_code=200, headers=headers)