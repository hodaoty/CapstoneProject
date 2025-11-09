# File: app/core/config.py
import os


class Settings:
    DATABASE_URL: str = os.environ.get("DATABASE_URL")


settings = Settings()
