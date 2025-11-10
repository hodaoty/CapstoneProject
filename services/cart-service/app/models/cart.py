from typing import List

from pydantic import BaseModel


class CartItemBase(BaseModel):
    """Một món hàng trong giỏ"""

    product_id: int
    quantity: int


class CartItemCreate(CartItemBase):
    """Dữ liệu nhận vào khi thêm/cập nhật giỏ hàng"""

    pass


class CartItem(CartItemBase):
    """Dữ liệu trả ra (nếu cần thêm thông tin sau này)"""

    pass


class Cart(BaseModel):
    """Toàn bộ giỏ hàng của user"""

    user_id: str
    items: List[CartItem] = []
