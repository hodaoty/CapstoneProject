from decimal import Decimal  # Sửa: Dùng Decimal
from typing import Optional

from pydantic import BaseModel


# Schema cơ sở
class ProductBase(BaseModel):
    name: str
    description: Optional[str] = None
    price: Decimal
    category: Optional[str] = None


# Schema khi tạo mới (sẽ nhận từ API)
class ProductCreate(ProductBase):
    pass


# Schema khi cập nhật (tất cả các trường đều là tùy chọn)
class ProductUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    price: Optional[Decimal] = None
    category: Optional[str] = None


# Schema khi đọc (sẽ trả về cho API)
class ProductRead(ProductBase):
    id: int

    class Config:
        from_attributes = True  # Cho phép Pydantic đọc từ SQLAlchemy model
