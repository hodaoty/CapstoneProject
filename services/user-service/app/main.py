from app.api.v1 import users  # <-- Import router users
from app.db import models
from app.db.database import engine
from fastapi import FastAPI

# Tạo bảng CSDL (vẫn như cũ)
models.Base.metadata.create_all(bind=engine)

app = FastAPI()

# Include router:
# Tất cả các API trong 'users.router' sẽ được thêm vào app
# Nó sẽ giữ nguyên các đường dẫn như /api/users/
app.include_router(users.router, prefix="/api", tags=["users"])


@app.get("/")
def read_root():
    return {"service": "User Service (Refactored) is running"}
