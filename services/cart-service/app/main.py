from app.api.v1 import cart
from fastapi import FastAPI

app = FastAPI(title="Cart Service")

app.include_router(cart.router, prefix="/api", tags=["cart"])


@app.get("/")
def read_root():
    """Endpoint Healthcheck"""
    return {"service": "Cart Service is running"}
