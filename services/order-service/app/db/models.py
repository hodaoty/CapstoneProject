# File: services/order-service/app/db/models.py
from app.db.database import Base
from sqlalchemy import (Column, DateTime, ForeignKey, Integer, Numeric, String,
                        func)
from sqlalchemy.orm import relationship


class Order(Base):
    __tablename__ = "orders"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(
        String, index=True, nullable=False
    )  # Dùng String nếu user_id là 'user123'
    total_price = Column(Numeric(10, 2), nullable=False)
    status = Column(
        String(50), nullable=False, default="PENDING"
    )  # (PENDING, COMPLETED, CANCELLED)

    shipping_address = Column(String(255), nullable=True)  # (Sẽ lấy từ user-service)

    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())

    # Mối quan hệ: Một Order có nhiều OrderItem
    items = relationship("OrderItem", back_populates="order")


class OrderItem(Base):
    __tablename__ = "order_items"

    id = Column(Integer, primary_key=True, index=True)
    product_id = Column(Integer, index=True, nullable=False)
    quantity = Column(Integer, nullable=False)

    # Lưu lại giá tại thời điểm mua hàng
    price_at_purchase = Column(Numeric(10, 2), nullable=False)

    order_id = Column(Integer, ForeignKey("orders.id"))

    # Mối quan hệ: Một OrderItem thuộc về một Order
    order = relationship("Order", back_populates="items")
