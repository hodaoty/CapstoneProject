from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional, List

from app.db.database import get_db
from app.services.product_service import (
    get_products, get_product, create_product,
    update_product, delete_product
)
from app.schemas.product import ProductCreate, ProductRead, ProductUpdate

router = APIRouter()

@router.get("/products", response_model=List[ProductRead])
def read_products(
    db: Session = Depends(get_db),
    skip: int = Query(0, ge=0, description="Number of items to skip"),
    limit: int = Query(10, ge=1, le=100, description="Number of items to return"),
    category: Optional[str] = Query(None, description="Filter by category"),
    min_price: Optional[float] = Query(None, ge=0, description="Minimum price"),
    max_price: Optional[float] = Query(None, ge=0, description="Maximum price"),
    search: Optional[str] = Query(None, description="Search by name or description"),
    sort_by: str = Query("id", description="Field to sort by"),
    sort_desc: bool = Query(False, description="Sort in descending order")
):
    return get_products(
        db, skip, limit, category,
        min_price, max_price, search,
        sort_by, sort_desc
    )


@router.get("/products/{product_id}", response_model=ProductRead)
def read_product(product_id: int, db: Session = Depends(get_db)):
    db_product = get_product(db, product_id)
    if not db_product:
        raise HTTPException(status_code=404, detail="Product not found")
    return db_product


@router.post("/products", response_model=ProductRead)
def create_new_product(product: ProductCreate, db: Session = Depends(get_db)):
    return create_product(db, product)


@router.put("/products/{product_id}", response_model=ProductRead)
def update_existing_product(
    product_id: int,
    product: ProductUpdate,
    db: Session = Depends(get_db)
):
    return update_product(db, product_id, product)


@router.delete("/products/{product_id}")
def delete_existing_product(product_id: int, db: Session = Depends(get_db)):
    return delete_product(db, product_id)
