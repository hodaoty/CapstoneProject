import os

# Đọc cấu hình MySQL từ biến môi trường
MYSQL_USER = os.environ.get("MYSQL_USER")
MYSQL_PASSWORD = os.environ.get("MYSQL_PASSWORD")
MYSQL_HOST = os.environ.get("MYSQL_HOST")
MYSQL_PORT = os.environ.get("MYSQL_PORT")
MYSQL_DB = os.environ.get("MYSQL_DB")

# Tạo chuỗi kết nối (connection string)
DATABASE_URL = (
    f"mysql+pymysql://{MYSQL_USER}:{MYSQL_PASSWORD}@"
    f"{MYSQL_HOST}:{MYSQL_PORT}/{MYSQL_DB}"
)


class Settings:
    DATABASE_URL: str = DATABASE_URL


settings = Settings()
