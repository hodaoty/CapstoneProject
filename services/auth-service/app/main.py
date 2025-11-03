from fastapi import FastAPI
from app.api.v1 import auth
from fastapi.middleware.cors import CORSMiddleware
app = FastAPI()

# Định nghĩa các nguồn (origin) được phép
origins = [
    "http://localhost",
    "http://localhost:5173",  # Cổng mặc định của Vite (React)
    "http://localhost:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],  # Cho phép tất cả các method (GET, POST, PUT...)
    allow_headers=["*"],  # Cho phép tất cả các header
)
app.include_router(auth.router, prefix="/api", tags=["authentication"])

@app.get("/")
def read_root():
    """
    Endpoint healthcheck mà docker-compose sử dụng.
    """
    return {"service": "Auth Service is running"}

