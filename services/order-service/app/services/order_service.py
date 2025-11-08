# File: services/order-service/app/services/order_service.py
from decimal import Decimal

import httpx
from app.core.config import settings
from app.db import models
from app.models.order import OrderCreate
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

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
    return "123 Đường ABC, Quận 1, TPHCM"  # Giả định


async def validate_item(
    client: httpx.AsyncClient, product_id: int, quantity_requested: int
) -> Decimal:
    """
    Kiểm tra giá và kho hàng.
    Trả về giá (nếu hợp lệ) hoặc ném Exception (nếu lỗi).
    """

    # 1. Gọi Product Service lấy giá MỚI NHẤT
    product_url = f"{settings.PRODUCT_SERVICE_URL}/products/{product_id}"
    product_response = await client.get(product_url)
    if product_response.status_code != 200:
        raise HTTPException(
            status_code=400, detail=f"Sản phẩm ID {product_id} không tồn tại"
        )

    price = Decimal(product_response.json()["price"])

    # 2. Gọi Inventory Service kiểm tra kho
    inventory_url = f"{settings.INVENTORY_SERVICE_URL}/inventory/{product_id}"
    inventory_response = await client.get(inventory_url)
    if inventory_response.status_code != 200:
        raise HTTPException(
            status_code=400, detail=f"Không tìm thấy kho cho sản phẩm ID {product_id}"
        )

    stock_quantity = inventory_response.json()["quantity"]

    if quantity_requested > stock_quantity:
        raise HTTPException(
            status_code=400,
            detail=f"Không đủ hàng cho sản phẩm ID {product_id} (Chỉ còn {stock_quantity})",
        )

    # 3. Mọi thứ OK, trả về giá
    return price


async def decrease_inventory(client: httpx.AsyncClient, product_id: int, quantity: int):
    """Gọi Inventory Service để TRỪ KHO"""
    url = f"{settings.INVENTORY_SERVICE_URL}/inventory/update"
    payload = {"product_id": product_id, "change_quantity": -abs(quantity)}  # Gửi số âm
    response = await client.post(url, json=payload)
    response.raise_for_status()  # Ném lỗi nếu trừ kho thất bại


async def clear_cart(client: httpx.AsyncClient, user_id: str):
    """Gọi Cart Service để XÓA GIỎ HÀNG"""
    url = f"{settings.CART_SERVICE_URL}/cart/{user_id}"
    await client.delete(url)


async def call_payment_service(
    client: httpx.AsyncClient, order_id: int, amount: Decimal
) -> dict:
    """Gọi Payment Service để xử lý thanh toán"""
    url = f"{settings.PAYMENT_SERVICE_URL}/payments/"
    payload = {
        "order_id": order_id,
        "amount": float(amount),
    }  # Chuyển Decimal thành float cho JSON

    try:
        response = await client.post(url, json=payload)
        response.raise_for_status()  # Ném lỗi nếu (500, 402)
        return response.json()
    except httpx.HTTPStatusError as e:
        # Nếu Payment Service trả về 402 (Payment Failed)
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail=f"Thanh toán thất bại: {e.response.json().get('detail')}",
        )


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
        validated_items = []

        # 3. Kiểm tra từng món hàng
        for item in cart_items:
            product_id = item["product_id"]
            quantity = item["quantity"]
            price = await validate_item(client, product_id, quantity)
            total_price += price * quantity
            validated_items.append(
                {
                    "product_id": product_id,
                    "quantity": quantity,
                    "price_at_purchase": price,
                }
            )

        # 4. Lưu Order (với trạng thái PENDING)
        # Chúng ta phải lưu trước để lấy Order ID
        db_order = models.Order(
            user_id=order_in.user_id,
            total_price=total_price,
            shipping_address=shipping_address,
            status="PENDING",  # Trạng thái chờ thanh toán
        )
        db.add(db_order)
        db.commit()  # Commit để lấy ID
        db.refresh(db_order)

        # 5. Gọi Payment Service (SỬA Ở ĐÂY)
        try:
            # payment_result = await call_payment_service(
            #     client, order_id=db_order.id, amount=total_price
            # )
            # Nếu thanh toán thành công, payment_result sẽ chứa thông tin giao dịch
            db_order.status = "COMPLETED"  # Cập nhật trạng thái
            db.add(db_order)

        except HTTPException as e:
            # Nếu thanh toán thất bại (lỗi 402)
            db_order.status = "PAYMENT_FAILED"
            db.add(db_order)
            db.commit()
            raise e  # Ném lỗi 402 về cho client

        # 6. Lưu OrderItems (chỉ sau khi thanh toán gần như OK)
        for v_item in validated_items:
            db_item = models.OrderItem(
                product_id=v_item["product_id"],
                quantity=v_item["quantity"],
                price_at_purchase=v_item["price_at_purchase"],
                order_id=db_order.id,
            )
            db.add(db_item)

        # 7. Trừ kho và Xóa giỏ hàng (Sau khi đã chắc chắn)
        try:
            for v_item in validated_items:
                await decrease_inventory(
                    client, v_item["product_id"], v_item["quantity"]
                )

            await clear_cart(client, order_in.user_id)

        except httpx.HTTPStatusError as e:
            # Nếu trừ kho lỗi (rất nghiêm trọng)
            db.rollback()
            db_order.status = "INVENTORY_FAILED"
            db.add(db_order)
            db.commit()
            raise HTTPException(
                status_code=500, detail=f"Thanh toán thành công nhưng lỗi trừ kho: {e}"
            )

        # 8. Hoàn tất
        db.commit()
        db.refresh(db_order)
        return db_order
