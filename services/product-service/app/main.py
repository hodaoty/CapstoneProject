from app.api.v1 import products
from app.db.database import Base, engine
from fastapi import FastAPI
import os 
Base.metadata.create_all(bind=engine)


app = FastAPI(title="Product Service")


app.include_router(products.router, prefix="/api", tags=["products"])


@app.get("/")
def read_root():
    return {"service": "Product Service is running"}
