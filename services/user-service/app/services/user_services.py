"""Create, Read, Update, Delete"""

from app.core.security import get_password_hash
from app.db import models
from app.models import user as schemas
from sqlalchemy.orm import Session


def get_user(db: Session, user_id: int):
    """Lấy 1 user bằng ID"""
    return db.query(models.User).filter(models.User.id == user_id).first()


def get_user_by_email(db: Session, email: str):
    """Lấy danh sách user"""
    return db.query(models.User).filter(models.User.email == email).first()


def get_users(db: Session, skip: int = 0, limit: int = 100):
    """Lấy danh sách user"""
    return db.query(models.User).offset(skip).limit(limit).all()


def create_user(db: Session, user: schemas.UserCreate):
    """Tạo user mới, sử dụng mật khẩu đã băm"""
    # Băm mật khẩu thay vì lưu thô
    hashed_password = get_password_hash(user.password)

    db_user = models.User(
        email=user.email, hashed_password=hashed_password  # Lưu mật khẩu đã băm
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def update_user(db: Session, user_id: int, user_in: schemas.UserUpdate):
    db_user = get_user(db, user_id=user_id)
    if not db_user:
        return None
    if user_in.email:
        db_user.email = user_in.email
    if user_in.password:
        db_user.hashed_password = get_password_hash(user_in.password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def delete_user(db: Session, user_id: int):
    db_user = get_user(db, user_id=user_id)
    if not db_user:
        return None
    db.delete(db_user)
    db.commit()
    return db_user
