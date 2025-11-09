from app.core.config import settings
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Lấy URL kết nối từ biến môi trường
# Cú pháp: postgresql://user:password@host/dbname
# DATABASE_URL = os.environ.get("DATABASE_URL")

engine = create_engine(settings.DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# Hàm helper để lấy 1 session nói chuyện với DB
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
