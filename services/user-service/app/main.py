from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

# Import các thành phần chúng ta vừa tạo
from . import models, schemas, crud
from .database import engine, get_db

# Lệnh này bảo SQLAlchemy tạo bảng "users" (nếu chưa có)
# khi ứng dụng khởi động
models.Base.metadata.create_all(bind=engine)

app = FastAPI()

@app.get("/")
def read_root():
    return {"service": "User Service is running with PostgreSQL"}

# API tạo user mới
@app.post("/api/users/", response_model=schemas.UserRead)
def create_user_endpoint(user: schemas.UserCreate, db: Session = Depends(get_db)):
    # Kiểm tra xem email đã tồn tại chưa
    db_user = crud.get_user_by_email(db, email=user.email)
    if db_user:
        # Nếu tồn tại, báo lỗi 400
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Nếu không, gọi hàm crud để tạo user
    return crud.create_user(db=db, user=user)

# API lấy danh sách user
@app.get("/api/users/", response_model=List[schemas.UserRead])
def read_users(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    users = db.query(models.User).offset(skip).limit(limit).all()
    return users

# === API LẤY 1 USER BẰNG ID (MỚI) ===
@app.get("/api/users/{user_id}", response_model=schemas.UserRead)
def read_user_endpoint(user_id: int, db: Session = Depends(get_db)):
    db_user = crud.get_user(db, user_id=user_id)
    if db_user is None:
        # Nếu không tìm thấy, báo lỗi 404
        raise HTTPException(status_code=404, detail="User not found")
    return db_user