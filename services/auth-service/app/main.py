from fastapi import FastAPI
from app.api.v1 import auth

app = FastAPI()

app.include_router(auth.router, prefix="/api", tags=["authentication"])

@app.get("/")
def read_root():
    """
    Endpoint healthcheck mà docker-compose sử dụng.
    """
    return {"service": "Auth Service is running"}

