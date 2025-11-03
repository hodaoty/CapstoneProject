from fastapi import FastAPI


from app.api.v1 import products


from app.db.database import Base, engine

from app.db.models import Product

Base.metadata.create_all(bind=engine)


app = FastAPI(title="Product Service")


app.include_router(products.router, prefix="/api/v1", tags=["products"])

@app.get("/")
def read_root():
    return {"service": "Product Service is running"}
