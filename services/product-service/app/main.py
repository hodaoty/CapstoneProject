from app.api.v1 import products
from app.db.database import Base, engine
from fastapi import FastAPI
import os 
from fastapi.staticfiles import StaticFiles

Base.metadata.create_all(bind=engine)


app = FastAPI(title="Product Service")
os.makedirs("/code/uploads", exist_ok=True)
app.mount("/api/products/images", StaticFiles(directory="/code/uploads"), name="images")

app.include_router(products.router, prefix="/api", tags=["products"])


@app.get("/")
def read_root():
    return {"service": "Product Service is running"}
