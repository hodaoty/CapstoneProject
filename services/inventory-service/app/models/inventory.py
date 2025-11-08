from pydantic import BaseModel


# Schema để đọc dữ liệu (GET)
class InventoryRead(BaseModel):
    product_id: int
    quantity: int

    class Config:
        from_attributes = True  # Cho phép Pydantic đọc từ SQLAlchemy


# Schema để cập nhật (POST/PUT)
# 'change_quantity' có thể là số âm (khi bán) hoặc số dương (khi nhập)
class InventoryUpdate(BaseModel):
    product_id: int
    change_quantity: int
