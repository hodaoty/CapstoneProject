from typing import Optional

from pydantic import BaseModel, EmailStr


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
        from_attributes = True  # Cho phép Pydantic đọc từ model SQLAlchemy


class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    password: Optional[str] = None


class UserReadWithPassword(UserRead):
    """
    Schema này kế thừa từ UserRead, nhưng thêm trường hashed_password.
    Chỉ dùng cho giao tiếp nội bộ (service-to-service).
    """

    hashed_password: str
