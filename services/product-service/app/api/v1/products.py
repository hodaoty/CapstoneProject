from typing import List

from app.db.database import get_db
from app.models import product as schemas
from app.services import product_service as crud
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

router = APIRouter()


# POST (Tạo sản phẩm)
@router.post("/products/", response_model=schemas.ProductRead)
def create_product_endpoint(
    product: schemas.ProductCreate, db: Session = Depends(get_db)
):
    db_product = crud.get_product_by_name(db, name=product.name)
    if db_product:
        raise HTTPException(status_code=400, detail="Product name already registered")
    return crud.create_product(db=db, product=product)


# GET (Lấy danh sách sản phẩm)
@router.get("/products/", response_model=List[schemas.ProductRead])
def read_products_endpoint(
    skip: int = 0, limit: int = 100, db: Session = Depends(get_db)
):
    products = crud.get_products(db, skip=skip, limit=limit)
    return products


# GET (Lấy 1 sản phẩm)
@router.get("/products/{product_id}", response_model=schemas.ProductRead)
def read_product_endpoint(product_id: int, db: Session = Depends(get_db)):
    db_product = crud.get_product(db, product_id=product_id)
    if db_product is None:
        raise HTTPException(status_code=404, detail="Product not found")
    return db_product


# PUT (Cập nhật sản phẩm)
@router.put("/products/{product_id}", response_model=schemas.ProductRead)
def update_product_endpoint(
    product_id: int, product_in: schemas.ProductUpdate, db: Session = Depends(get_db)
):
    db_product = crud.get_product(db, product_id=product_id)
    if db_product is None:
        raise HTTPException(status_code=404, detail="Product not found")

    # Kiểm tra nếu tên mới đã tồn tại (và không phải là chính nó)
    if product_in.name:
        existing_product = crud.get_product_by_name(db, name=product_in.name)
        if existing_product and existing_product.id != product_id:
            raise HTTPException(
                status_code=400, detail="Product name already registered"
            )

    return crud.update_product(db=db, db_product=db_product, product_in=product_in)


# DELETE (Xóa sản phẩm)
@router.delete("/products/{product_id}", response_model=schemas.ProductRead)
def delete_product_endpoint(product_id: int, db: Session = Depends(get_db)):
    db_product = crud.get_product(db, product_id=product_id)
    if db_product is None:
        raise HTTPException(status_code=404, detail="Product not found")
    return crud.delete_product(db=db, db_product=db_product)
