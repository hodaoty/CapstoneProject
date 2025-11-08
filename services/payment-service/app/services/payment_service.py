import uuid  # Để tạo transaction_id giả

from app.db import models
from app.models.payment import PaymentCreate
from sqlalchemy.orm import Session


def process_payment(db: Session, payment_in: PaymentCreate) -> models.Payment:
    """
    Giả lập (mock) quá trình xử lý thanh toán.
    Trong thực tế, đây là nơi bạn gọi Stripe/MoMo.
    """

    # 1. Tạo bản ghi thanh toán trong CSDL
    db_payment = models.Payment(
        order_id=payment_in.order_id, amount=payment_in.amount, status="PENDING"
    )
    db.add(db_payment)
    db.commit()
    db.refresh(db_payment)

    # 2. Giả lập gọi API bên thứ 3 (và nó luôn thành công)
    is_successful = True

    if is_successful:
        db_payment.status = "SUCCESS"
        db_payment.transaction_id = f"mock_tx_{uuid.uuid4()}"  # Tạo ID giao dịch giả
    else:
        db_payment.status = "FAILED"

    db.add(db_payment)
    db.commit()
    db.refresh(db_payment)

    return db_payment
