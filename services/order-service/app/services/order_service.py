# File: services/order-service/app/services/order_service.py
import httpx
from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from decimal import Decimal

from app.db import models
from app.models.order import OrderCreate, OrderRead
from app.core.config import settings

# --- Các hàm gọi API nội bộ ---

async def fetch_cart(client: httpx.AsyncClient, user_id: str) -> dict:
    """Gọi Cart Service để lấy giỏ hàng"""
    url = f"{settings.CART_SERVICE_URL}/cart/{user_id}"
    response = await client.get(url)
    if response.status_code != 200:
        raise HTTPException(status_code=404, detail="Không tìm thấy giỏ hàng")
    return response.json()

async def fetch_user_address(client: httpx.AsyncClient, user_id: str) -> str:
    """Gọi User Service để lấy địa chỉ (Giả sử API này tồn tại)"""
    # Ghi chú: user-service của bạn chưa có API này.
    # Chúng ta sẽ dùng địa chỉ giả định
    # url = f"{settings.USER_SERVICE_URL}/users/{user_id}/address"
    # response = await client.get(url)
    # return response.json().get("address", "Địa chỉ mặc định")
    return "123 Đường ABC, Quận 1, TPHCM" # Giả định

async def validate_item(client: httpx.AsyncClient, product_id: int, quantity_requested: int) -> Decimal:
    """
    Kiểm tra giá và kho hàng.
    Trả về giá (nếu hợp lệ) hoặc ném Exception (nếu lỗi).
    """
    
    # 1. Gọi Product Service lấy giá MỚI NHẤT
    product_url = f"{settings.PRODUCT_SERVICE_URL}/products/{product_id}"
    product_response = await client.get(product_url)
    if product_response.status_code != 200:
        raise HTTPException(status_code=400, detail=f"Sản phẩm ID {product_id} không tồn tại")
    
    price = Decimal(product_response.json()["price"])

    # 2. Gọi Inventory Service kiểm tra kho
    inventory_url = f"{settings.INVENTORY_SERVICE_URL}/inventory/{product_id}"
    inventory_response = await client.get(inventory_url)
    if inventory_response.status_code != 200:
        raise HTTPException(status_code=400, detail=f"Không tìm thấy kho cho sản phẩm ID {product_id}")
    
    stock_quantity = inventory_response.json()["quantity"]
    
    if quantity_requested > stock_quantity:
        raise HTTPException(status_code=400, detail=f"Không đủ hàng cho sản phẩm ID {product_id} (Chỉ còn {stock_quantity})")

    # 3. Mọi thứ OK, trả về giá
    return price

async def decrease_inventory(client: httpx.AsyncClient, product_id: int, quantity: int):
    """Gọi Inventory Service để TRỪ KHO"""
    url = f"{settings.INVENTORY_SERVICE_URL}/inventory/update"
    payload = {"product_id": product_id, "change_quantity": -abs(quantity)} # Gửi số âm
    response = await client.post(url, json=payload)
    response.raise_for_status() # Ném lỗi nếu trừ kho thất bại

async def clear_cart(client: httpx.AsyncClient, user_id: str):
    """Gọi Cart Service để XÓA GIỎ HÀNG"""
    url = f"{settings.CART_SERVICE_URL}/cart/{user_id}"
    await client.delete(url)

# --- Hàm Logic chính ---

async def create_new_order(db: Session, order_in: OrderCreate) -> models.Order:
    
    async with httpx.AsyncClient() as client:
        
        # 1. Lấy giỏ hàng
        cart = await fetch_cart(client, order_in.user_id)
        cart_items = cart.get("items", [])
        if not cart_items:
            raise HTTPException(status_code=400, detail="Giỏ hàng trống")

        # 2. Lấy địa chỉ
        shipping_address = await fetch_user_address(client, order_in.user_id)
        
        total_price = Decimal(0)
        validated_items = [] # Danh sách các item đã kiểm tra (giá + số lượng)
        
        # 3. Kiểm tra từng món hàng (Quan trọng)
        for item in cart_items:
            product_id = item["product_id"]
            quantity = item["quantity"]
            
            # Hàm này sẽ ném lỗi (HTTPException) nếu có vấn đề
            price = await validate_item(client, product_id, quantity)
            
            total_price += (price * quantity)
            validated_items.append({
                "product_id": product_id,
                "quantity": quantity,
                "price_at_purchase": price
            })

        # 4. (Giả định) Thanh toán thành công
        # (Sau này sẽ gọi Payment Service ở đây)
        payment_ok = True 
        
        if not payment_ok:
            raise HTTPException(status_code=402, detail="Thanh toán thất bại")

        # 5. Lưu vào Database (Tạo Order và OrderItems)
        db_order = models.Order(
            user_id=order_in.user_id,
            total_price=total_price,
            shipping_address=shipping_address,
            status="COMPLETED" # Giả định thanh toán xong
        )
        db.add(db_order)
        db.flush() # Lấy ID của order mới

        for v_item in validated_items:
            db_item = models.OrderItem(
                product_id=v_item["product_id"],
                quantity=v_item["quantity"],
                price_at_purchase=v_item["price_at_purchase"],
                order_id=db_order.id
            )
            db.add(db_item)

        # 6. Trừ kho và Xóa giỏ hàng (Sau khi đã chắc chắn)
        try:
            for v_item in validated_items:
                await decrease_inventory(client, v_item["product_id"], v_item["quantity"])
            
            await clear_cart(client, order_in.user_id)
        
        except httpx.HTTPStatusError as e:
            # Nếu trừ kho hoặc xóa giỏ hàng lỗi
            db.rollback() # HỦY TOÀN BỘ GIAO DỊCH
            raise HTTPException(status_code=500, detail=f"Lỗi khi cập nhật kho/giỏ hàng: {e}")
        except Exception as e:
            db.rollback()
            raise HTTPException(status_code=500, detail=f"Lỗi hệ thống: {e}")

        # 7. Hoàn tất
        db.commit()
        db.refresh(db_order)
        return db_order