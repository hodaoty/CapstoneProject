from pydantic import BaseModel, Field, field_validator
from typing import Optional


class ProductBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=255)
    price: float = Field(..., gt=0)
    stock: int = Field(0, ge=0)
    category: Optional[str] = Field(None, max_length=50)

    @field_validator('price')
    def round_price(cls, v):
        return round(v, 2)  # Làm tròn 2 chữ số thập phân


# ---- Create schema ----
class ProductCreate(ProductBase):
    pass


# ---- Update schema ----
class ProductUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=255)
    price: Optional[float] = Field(None, gt=0)
    stock: Optional[int] = Field(None, ge=0)
    category: Optional[str] = Field(None, max_length=50)

    @field_validator('price')
    def round_price(cls, v):
        if v is not None:
            return round(v, 2)
        return v


# ---- Read schema ----
class ProductRead(ProductBase):
    id: int

    class Config:
        from_attributes = True  # Dùng thay cho orm_mode ở Pydantic v2
