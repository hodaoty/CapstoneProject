import os


class Settings:
    REDIS_URL: str = os.environ.get("REDIS_URL", "redis://localhost:6379")


settings = Settings()
