import os


class Settings:
    REDIS_URL: str = os.environ.get("REDIS_URL", "redis://localhost:6379")
    JWT_SECRET_KEY: str = os.environ.get("JWT_SECRET_KEY", "secret")
    JWT_ALGORITHM: str = os.environ.get("JWT_ALGORITHM", "HS256")


settings = Settings()
