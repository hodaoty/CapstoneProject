# File: app/api/v1/users.py
from typing import List

from app.db.database import get_db
from app.models import user as schemas
from app.services import user_services as crud
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

router = APIRouter()


@router.post("/users/", response_model=schemas.UserRead)
def create_user_endpoint(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = crud.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    return crud.create_user(db=db, user=user)


@router.get("/users/", response_model=List[schemas.UserRead])
def read_users_endpoint(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    users = crud.get_users(db, skip=skip, limit=limit)
    return users


@router.get("/users/by-email/{email}", response_model=schemas.UserReadWithPassword)
def read_user_by_email_endpoint(email: str, db: Session = Depends(get_db)):
    """
    API nội bộ: Lấy thông tin user bằng email (bao gồm cả password đã băm).
    """
    db_user = crud.get_user_by_email(db, email=email)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


@router.get("/users/{user_id}", response_model=schemas.UserRead)
def read_user_endpoint(user_id: int, db: Session = Depends(get_db)):
    db_user = crud.get_user(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


@router.put("/users/{user_id}", response_model=schemas.UserRead)
def update_user_endpoint(
    user_id: int, user_in: schemas.UserUpdate, db: Session = Depends(get_db)
):
    db_user = crud.update_user(db, user_id=user_id, user_in=user_in)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


@router.delete("/users/{user_id}", response_model=schemas.UserRead)
def delete_user_endpoint(user_id: int, db: Session = Depends(get_db)):
    db_user = crud.delete_user(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user
