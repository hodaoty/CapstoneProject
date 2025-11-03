# Import BaseSettings từ Pydantic để quản lý cấu hình (settings)
from pydantic_settings import BaseSettings

# Lớp Settings chứa các biến môi trường cần thiết cho service
class Settings(BaseSettings):
    MYSQL_HOST: str
    MYSQL_PORT: int
    MYSQL_USER: str
    MYSQL_PASSWORD: str
    MYSQL_DB: str


# Tạo một instance settings để import dùng ở nơi khác
settings = Settings()
