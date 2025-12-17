import redis
from app.api.deps import get_current_user_email
from app.db.database import get_redis_db
from app.models.cart import Cart, CartItemCreate
from app.services import cart_service as crud
from fastapi import APIRouter, Depends

router = APIRouter()


# GET (Lấy giỏ hàng)
@router.get("/", response_model=Cart)
def read_cart(
    db: redis.Redis = Depends(get_redis_db),
    user_id: str = Depends(get_current_user_email),
):
    return crud.get_cart(db, user_id)


# POST (Thêm/cập nhật sản phẩm)
@router.post("/", response_model=Cart)
def update_cart_item(
    item: CartItemCreate,
    db: redis.Redis = Depends(get_redis_db),
    user_id: str = Depends(get_current_user_email),
):
    return crud.add_item_to_cart(db, user_id, item)


# DELETE (Xóa 1 sản phẩm)
@router.delete("/item/{product_id}", response_model=Cart)
def remove_cart_item(
    product_id: int,
    db: redis.Redis = Depends(get_redis_db),
    user_id: str = Depends(get_current_user_email),
):
    return crud.remove_item_from_cart(db, user_id, product_id)


# DELETE (Xóa sạch giỏ hàng)
@router.delete("/")
def delete_cart(
    db: redis.Redis = Depends(get_redis_db),
    user_id: str = Depends(get_current_user_email),
):
    return crud.clear_cart(db, user_id)
