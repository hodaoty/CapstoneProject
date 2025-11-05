from fastapi import FastAPI
from app.api.v1 import payments
from app.db.database import engine, Base

# Yêu cầu SQLAlchemy tạo bảng "payments"
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Payment Service")

# Đặt prefix chuẩn
app.include_router(payments.router, prefix="/api", tags=["payments"])

@app.get("/")
def read_root():
    """Endpoint Healthcheck"""
    return {"service": "Payment Service is running"}