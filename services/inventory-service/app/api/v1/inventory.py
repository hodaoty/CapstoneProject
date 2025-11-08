from app.db.database import get_db
from app.models.inventory import InventoryRead, InventoryUpdate
from app.services import inventory_service as crud
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

router = APIRouter()


@router.get("/inventory/{product_id}", response_model=InventoryRead)
def get_product_stock(product_id: int, db: Session = Depends(get_db)):
    """API công khai: Kiểm tra số lượng tồn kho của 1 sản phẩm."""
    return crud.get_stock(db, product_id)


@router.post("/inventory/update", response_model=InventoryRead)
def update_product_stock(update_data: InventoryUpdate, db: Session = Depends(get_db)):
    """
    API nội bộ: Cập nhật kho (Order Service sẽ gọi cái này).
    (Sau này sẽ bảo vệ API này, chỉ cho service nội bộ gọi)
    """
    return crud.update_stock(db, update_data)
