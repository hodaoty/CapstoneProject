from app.db.database import get_db
from app.models.payment import PaymentCreate, PaymentRead
from app.services import payment_service as crud
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

router = APIRouter()


@router.post("/payments/", response_model=PaymentRead)
def create_payment(payment_in: PaymentCreate, db: Session = Depends(get_db)):
    """
    API nội bộ: Order Service sẽ gọi API này để xử lý thanh toán.
    """
    payment = crud.process_payment(db, payment_in)
    if payment.status != "SUCCESS":
        raise HTTPException(status_code=402, detail="Payment Failed")

    return payment
