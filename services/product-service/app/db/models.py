from app.db.database import Base
from sqlalchemy import Column, DateTime, Integer, Numeric, String, Text, func


class Product(Base):
    __tablename__ = "products_official"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    price = Column(Numeric(10, 2), nullable=False)  # Sua price
    # Xoa stock vi inventory-service dam nhan trach nhiem do
    category = Column(String(50), nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
