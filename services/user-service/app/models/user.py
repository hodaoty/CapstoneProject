from pydantic import BaseModel, EmailStr
from typing import Optional
# Schema cho dữ liệu nhận vào (tạo user)
class UserCreate(BaseModel):
    email: EmailStr
    password: str

# Schema cho dữ liệu trả ra (đọc user)
class UserRead(BaseModel):
    id: int
    email: EmailStr
    is_active: bool

    class Config:
        from_attributes = True # Cho phép Pydantic đọc từ model SQLAlchemy

class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    password: Optional[str] = None