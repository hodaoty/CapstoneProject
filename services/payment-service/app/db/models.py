from app.db.database import Base
from sqlalchemy import Column, DateTime, Integer, Numeric, String, func


class Payment(Base):
    __tablename__ = "payments"

    id = Column(Integer, primary_key=True, index=True)
    order_id = Column(Integer, unique=True, index=True, nullable=False)
    amount = Column(Numeric(10, 2), nullable=False)
    status = Column(
        String(50), nullable=False, default="PENDING"
    )  # PENDING, SUCCESS, FAILED
    payment_gateway = Column(String(50), default="mock")
    transaction_id = Column(String(100), unique=True, index=True, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
