# Import các kiểu dữ liệu cần thiết
from sqlalchemy import Column, Integer, String, Float, DateTime, func
from app.db.database import Base

# ORM Model ánh xạ với bảng 'products' trong MySQL
class Product(Base):
    __tablename__ = "products"  # Tên bảng

    # Cột id: khóa chính (PRIMARY KEY), tự tăng (AUTO_INCREMENT)
    id = Column(Integer, primary_key=True, index=True)

    # Cột name: tên sản phẩm, bắt buộc có, và duy nhất
    name = Column(String(100), unique=True, nullable=False)

    # Cột description: mô tả sản phẩm, có thể trống
    description = Column(String(255))

    # Cột price: giá sản phẩm, bắt buộc
    price = Column(Float, nullable=False)

    # Cột stock: tồn kho, mặc định 0
    stock = Column(Integer, default=0)

    # Cột category: loại sản phẩm
    category = Column(String(50))

    # created_at: ngày tạo, tự động gán thời gian hiện tại
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # updated_at: ngày cập nhật, tự động cập nhật mỗi lần update
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
