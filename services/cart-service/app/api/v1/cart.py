import redis
from app.db.database import get_redis_db
from app.models.cart import Cart, CartItemCreate
from app.services import cart_service as crud
from fastapi import APIRouter, Depends

router = APIRouter()


# GET (Lấy giỏ hàng)
@router.get("/cart/{user_id}", response_model=Cart)
def read_cart(user_id: str, db: redis.Redis = Depends(get_redis_db)):
    return crud.get_cart(db, user_id)


# POST (Thêm/cập nhật sản phẩm)
@router.post("/cart/{user_id}", response_model=Cart)
def update_cart_item(
    user_id: str, item: CartItemCreate, db: redis.Redis = Depends(get_redis_db)
):
    return crud.add_item_to_cart(db, user_id, item)


# DELETE (Xóa 1 sản phẩm)
@router.delete("/cart/{user_id}/item/{product_id}", response_model=Cart)
def remove_cart_item(
    user_id: str, product_id: int, db: redis.Redis = Depends(get_redis_db)
):
    return crud.remove_item_from_cart(db, user_id, product_id)


# DELETE (Xóa sạch giỏ hàng)
@router.delete("/cart/{user_id}")
def delete_cart(user_id: str, db: redis.Redis = Depends(get_redis_db)):
    return crud.clear_cart(db, user_id)
