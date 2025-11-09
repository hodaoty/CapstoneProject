from app.db import models
from app.models.inventory import InventoryUpdate
from fastapi import HTTPException, status
from sqlalchemy.orm import Session


def get_stock(db: Session, product_id: int) -> models.Inventory:
    """Lấy số lượng tồn kho theo product_id"""
    item = (
        db.query(models.Inventory)
        .filter(models.Inventory.product_id == product_id)
        .first()
    )

    if not item:
        # Nếu sản phẩm chưa có trong kho, tạo mới với số lượng 0
        # (Không commit vội, chỉ trả về object)
        return models.Inventory(product_id=product_id, quantity=0)
    return item


def update_stock(db: Session, update_data: InventoryUpdate) -> models.Inventory:
    """Cập nhật số lượng (tăng hoặc giảm)"""

    # Dùng FOR UPDATE để khóa hàng (row) này lại, tránh 2 đơn hàng
    # cùng lúc trừ kho (ngăn ngừa race condition)
    item = (
        db.query(models.Inventory)
        .filter(models.Inventory.product_id == update_data.product_id)
        .with_for_update()
        .first()
    )

    # Nếu sản phẩm chưa có trong kho
    if not item:
        if update_data.change_quantity < 0:
            # Không thể trừ kho nếu số lượng là 0
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Hết hàng"
            )

        # Tạo mới
        item = models.Inventory(
            product_id=update_data.product_id, quantity=update_data.change_quantity
        )
        db.add(item)
    else:
        # Nếu đã có, cập nhật
        item.quantity += update_data.change_quantity

    # Kiểm tra xem có bị âm kho không
    if item.quantity < 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Không đủ hàng trong kho"
        )

    db.commit()
    db.refresh(item)
    return item
