from app.api.deps import get_current_user_email
from app.db.database import get_db
from app.models.order import OrderCreate, OrderRead
from app.services import order_service as crud
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# POST /api/orders/
@router.post("/orders/", response_model=OrderRead)
async def create_order_endpoint(
    order_in: OrderCreate,
    db: Session = Depends(get_db),
    current_user_email: str = Depends(get_current_user_email),
    token: str = Depends(oauth2_scheme),
):
    """
    Tạo đơn hàng. Yêu cầu có Token đăng nhập.
    """
    try:
        new_order = await crud.create_new_order(
            db=db, order_in=order_in, user_id=current_user_email, token=token
        )
        return new_order
    except HTTPException as e:
        raise e  # Gửi lại lỗi (ví dụ: "Hết hàng")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
