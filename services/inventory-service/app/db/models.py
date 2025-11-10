from app.db.database import Base
from sqlalchemy import Column, Integer


class Inventory(Base):
    __tablename__ = "inventory"

    id = Column(Integer, primary_key=True, index=True)

    # product_id phải là duy nhất (unique)
    product_id = Column(Integer, unique=True, index=True, nullable=False)
    quantity = Column(Integer, nullable=False, default=0)
