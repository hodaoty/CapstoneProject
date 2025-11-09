import redis
from app.models.cart import Cart, CartItem, CartItemCreate

# Key trong Redis co dang "cart:123" voi "123" la user_id
CART_KEY_PREFIX = "cart:"


def _get_cart_key(user_id: str) -> str:
    """Tao key cho redis hash"""
    return f"{CART_KEY_PREFIX}{user_id}"


def get_cart(db: redis.Redis, user_id: str) -> Cart:
    """Lay toan bo gio hang cua user tu Redis hash"""
    cart_key = _get_cart_key(user_id)
    # Lấy tất cả (HGETALL) các field (product_id) và value (quantity)
    cart_data = db.hgetall(cart_key)

    cart_items = []
    # Chuyển đổi dữ liệu từ Redis (dict string) sang Pydantic model
    for product_id_str, quantity_str in cart_data.items():
        cart_items.append(
            CartItem(product_id=int(product_id_str), quantity=int(quantity_str))
        )
    return Cart(user_id=user_id, items=cart_items)


def add_item_to_cart(db: redis.Redis, user_id: str, item: CartItemCreate) -> Cart:
    """Thêm/Cập nhật một sản phẩm trong giỏ hàng"""
    cart_key = _get_cart_key(user_id)

    # Dùng HINCRBY (Hash Increment By)
    # Tự động cộng 'item.quantity' vào 'item.product_id'
    # Nếu product_id chưa tồn tại, nó sẽ tạo mới
    db.hincrby(cart_key, str(item.product_id), item.quantity)

    # Trả về giỏ hàng đã cập nhật
    return get_cart(db, user_id)


def remove_item_from_cart(db: redis.Redis, user_id: str, product_id: int) -> Cart:
    """Xóa 1 sản phẩm khỏi giỏ hàng"""
    cart_key = _get_cart_key(user_id)

    # Dùng HDEL (Hash Delete)
    db.hdel(cart_key, str(product_id))

    return get_cart(db, user_id)


def clear_cart(db: redis.Redis, user_id: str):
    """Xóa sạch giỏ hàng (khi đã thanh toán)"""
    cart_key = _get_cart_key(user_id)

    # Dùng DEL (xóa toàn bộ key)
    db.delete(cart_key)
    return {"status": "cart cleared"}
