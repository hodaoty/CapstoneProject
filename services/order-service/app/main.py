# File: services/order-service/app/main.py
from app.api.v1 import orders
from app.db.database import Base, engine
from fastapi import FastAPI

# Yêu cầu SQLAlchemy tạo bảng "orders" và "order_items"
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Order Service")

app.include_router(orders.router, prefix="/api", tags=["orders"])


@app.get("/")
def read_root():
    """Endpoint Healthcheck"""
    return {"service": "Order Service is running"}
