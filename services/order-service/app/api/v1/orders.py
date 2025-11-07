
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from app.db.database import get_db
from app.services import order_service as crud
from app.models.order import OrderCreate, OrderRead

router = APIRouter()

# POST /api/orders/
@router.post("/orders/", response_model=OrderRead)
async def create_order_endpoint(order: OrderCreate, db: Session = Depends(get_db)):
    """
    Tạo một đơn hàng mới.
    Đây là API chính, nó sẽ tự động gọi các service khác.
    """
    try:
        new_order = await crud.create_new_order(db=db, order_in=order)
        return new_order
    except HTTPException as e:
        raise e # Gửi lại lỗi (ví dụ: "Hết hàng")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

