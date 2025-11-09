from app.db import models
from app.models import product as schemas
from sqlalchemy.orm import Session


# Lay san pham dua tren id
def get_product(db: Session, product_id: int):
    return db.query(models.Product).filter(models.Product.id == product_id).first()


# lay san pham dua theo ten
def get_product_by_name(db: Session, name: str):
    return db.query(models.Product).filter(models.Product.name == name).first()


# lay tat ca san pham
def get_products(db: Session, skip: int = 0, limit: int = 100):
    return db.query(models.Product).offset(skip).limit(limit).all()


# Tao moi san pham (Da xoa stock)
def create_product(db: Session, product: schemas.ProductCreate):
    db_product = models.Product(
        name=product.name,
        description=product.description,
        price=product.price,
        category=product.category,
    )
    db.add(db_product)
    db.commit()
    db.refresh(db_product)
    return db_product


# update san pham
def update_product(
    db: Session, db_product: models.Product, product_in: schemas.ProductUpdate
):
    update_data = product_in.model_dump(exclude_unset=True)

    for key, value in update_data.items():
        setattr(db_product, key, value)

    db.add(db_product)
    db.commit()
    db.refresh(db_product)
    return db_product


# Xoa san pham
def delete_product(db: Session, db_product: models.Product):
    db.delete(db_product)
    db.commit()
    return db_product
