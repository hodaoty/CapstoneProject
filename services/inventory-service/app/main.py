from app.api.v1 import inventory
from app.db.database import Base, engine
from fastapi import FastAPI

# Yêu cầu SQLAlchemy tạo bảng "inventory" khi khởi động
Base.metadata.create_all(bind=engine)

app = FastAPI()

app.include_router(inventory.router, prefix="/api", tags=["inventory"])


@app.get("/")
def read_root():
    """Endpoint Healthcheck"""
    return {"service": "Inventory Service is running"}
