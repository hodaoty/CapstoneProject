import os


class Settings:
    DATABASE_URL: str = os.environ.get("DATABASE_URL")
    USER_SERVICE_URL: str = os.environ.get("USER_SERVICE_URL")
    PRODUCT_SERVICE_URL: str = os.environ.get("PRODUCT_SERVICE_URL")
    INVENTORY_SERVICE_URL: str = os.environ.get("INVENTORY_SERVICE_URL")
    CART_SERVICE_URL: str = os.environ.get("CART_SERVICE_URL")
    PAYMENT_SERVICE_URL: str = os.environ.get("PAYMENT_SERVICE_URL")


settings = Settings()
