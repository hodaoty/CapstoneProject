# Import các module cần thiết từ SQLAlchemy
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# Import settings (đã đọc từ .env)
from app.core.config import settings

# Tạo URL kết nối MySQL theo format của SQLAlchemy
DATABASE_URL = (
    f"mysql+pymysql://{settings.MYSQL_USER}:{settings.MYSQL_PASSWORD}"
    f"@{settings.MYSQL_HOST}:{settings.MYSQL_PORT}/{settings.MYSQL_DB}"
)

# Tạo engine để SQLAlchemy kết nối với database
# echo=True giúp in ra câu SQL để debug
engine = create_engine(DATABASE_URL, echo=True)

# Tạo session để thao tác dữ liệu (insert, update, query...)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base là lớp gốc dùng để định nghĩa ORM models (ví dụ class Product)
Base = declarative_base()

# Dependency dùng trong FastAPI: mỗi request sẽ có 1 session riêng
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
