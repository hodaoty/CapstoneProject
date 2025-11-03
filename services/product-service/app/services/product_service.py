# Import các module cần thiết
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_
from sqlalchemy.exc import IntegrityError
from fastapi import HTTPException
from typing import Optional, List
from app.db import models
from app.models.product import Product          # ORM model
from app.schemas.product import ProductCreate, ProductUpdate  # Pydantic schema

def get_products(
    db: Session,
    skip: int = 0,
    limit: int = 10,
    category: Optional[str] = None,
    min_price: Optional[float] = None,
    max_price: Optional[float] = None,
    search: Optional[str] = None,
    sort_by: str = "id",
    sort_desc: bool = False
):
    query = db.query(Product)

    if category:
        query = query.filter(Product.category == category)
    if min_price is not None:
        query = query.filter(Product.price >= min_price)
    if max_price is not None:
        query = query.filter(Product.price <= max_price)
    if search:
        search_filter = f"%{search}%"
        query = query.filter(
            or_(
                Product.name.ilike(search_filter),
                Product.description.ilike(search_filter)
            )
        )

    if hasattr(Product, sort_by):
        order_column = getattr(Product, sort_by)
        if sort_desc:
            order_column = order_column.desc()
        query = query.order_by(order_column)

    products = query.offset(skip).limit(limit).all()
    return products


def get_product(db: Session, product_id: int):
    return db.query(Product).filter(Product.id == product_id).first()


def create_product(db: Session, product: ProductCreate):
    try:
        existing_product = db.query(Product).filter(Product.name == product.name).first()
        if existing_product:
            raise HTTPException(status_code=400, detail="Product with this name already exists")

        db_product = Product(**product.dict())
        db.add(db_product)
        db.commit()
        db.refresh(db_product)
        return db_product
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Database error occurred while creating product")


def update_product(db: Session, product_id: int, product: ProductUpdate):
    try:
        db_product = get_product(db, product_id)
        if not db_product:
            raise HTTPException(status_code=404, detail="Product not found")

        for field, value in product.dict(exclude_unset=True).items():
            setattr(db_product, field, value)

        db.commit()
        db.refresh(db_product)
        return db_product
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Database error occurred while updating product")


def delete_product(db: Session, product_id: int):
    db_product = get_product(db, product_id)
    if not db_product:
        raise HTTPException(status_code=404, detail="Product not found")

    db.delete(db_product)
    db.commit()
    return {"message": "Product deleted successfully"}