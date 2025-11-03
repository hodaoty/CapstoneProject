# File: app/main.py (NỘI DUNG MỚI)
from fastapi import FastAPI
from app.api.v1 import users  # <-- Import router users
from app.db import models
from app.db.database import engine
from fastapi.middleware.cors import CORSMiddleware
# Tạo bảng CSDL (vẫn như cũ)
models.Base.metadata.create_all(bind=engine)

app = FastAPI()

origins = [
    "http://localhost",
    "http://localhost:5173",  # Cổng của React/Vite
    "http://localhost:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# Include router:
# Tất cả các API trong 'users.router' sẽ được thêm vào app
# Nó sẽ giữ nguyên các đường dẫn như /api/users/
app.include_router(users.router, prefix="/api", tags=["users"])

@app.get("/")
def read_root():
    return {"service": "User Service (Refactored) is running"}