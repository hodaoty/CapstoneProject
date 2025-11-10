import os


class Settings:
    # Biến môi trường cho Redis
    REDIS_URL: str = os.environ.get("REDIS_URL", "redis://localhost:6379")

    # Biến môi trường cho JWT
    JWT_SECRET_KEY: str = os.environ.get("JWT_SECRET_KEY", "secret")
    JWT_ALGORITHM: str = os.environ.get("JWT_ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(
        os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", 30)
    )
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7  # 7 ngày se refresh db 1 lan

    # URL của User Service (để gọi nội bộ)
    USER_SERVICE_URL: str = os.environ.get(
        "USER_SERVICE_URL", "http://localhost:8000/api"
    )


settings = Settings()
