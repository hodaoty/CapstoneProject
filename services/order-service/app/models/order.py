# File: services/order-service/app/models/order.py
from datetime import datetime
from decimal import Decimal
from typing import List, Optional

from pydantic import BaseModel


# --- Schemas cho OrderItem ---
class OrderItemBase(BaseModel):
    product_id: int
    quantity: int
    price_at_purchase: Decimal


class OrderItemCreate(OrderItemBase):
    pass


class OrderItemRead(OrderItemBase):
    id: int
    order_id: int

    class Config:
        from_attributes = True


# --- Schemas cho Order ---
class OrderBase(BaseModel):
    user_id: str
    shipping_address: Optional[str] = None


class OrderCreate(BaseModel):
    """Đây là dữ liệu API (POST /api/orders) nhận vào"""

    user_id: str
    # (API sẽ tự lấy địa chỉ, giỏ hàng, và tính tổng giá)


class OrderRead(OrderBase):
    """Đây là dữ liệu API trả về"""

    id: int
    total_price: Decimal
    status: str
    created_at: datetime
    items: List[OrderItemRead] = []  # Trả về các item con

    class Config:
        from_attributes = True
