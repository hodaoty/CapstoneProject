from pydantic import BaseModel
from typing import Optional
from decimal import Decimal
from datetime import datetime

class PaymentCreate(BaseModel):
    """Dữ liệu nhận vào từ Order Service"""
    order_id: int
    amount: Decimal

class PaymentRead(BaseModel):
    """Dữ liệu trả về"""
    id: int
    order_id: int
    amount: Decimal
    status: str
    transaction_id: Optional[str] = None
    created_at: datetime
    
    class Config:
        from_attributes = True