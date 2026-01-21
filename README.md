# **Hệ Thống E-commerce Microservices (Capstone Project)**

Đây là một dự án E-commerce toàn diện được xây dựng dựa trên kiến trúc **Microservices**. Dự án bao gồm hệ thống Backend mạnh mẽ với 7 dịch vụ độc lập, giao tiếp qua API Gateway, và một giao diện Frontend hiện đại được viết hoàn toàn bằng Python (NiceGUI).

Hệ thống được thiết kế để mô phỏng quy trình mua sắm thực tế, bao gồm quản lý người dùng, sản phẩm, kho hàng, giỏ hàng, đặt hàng và thanh toán, với cơ chế bảo mật và phân quyền (RBAC) đầy đủ.

## **Kiến trúc Hệ thống**

Dự án sử dụng mô hình **Hub-and-Spoke** với **Nginx API Gateway** làm trung tâm điều phối mọi luồng dữ liệu.

### **Sơ đồ luồng dữ liệu (Data Flow)**

1. **Frontend/Client** gửi request đến **API Gateway** (Port 80).  
2. **API Gateway** định tuyến request đến service cụ thể (User, Product, Order...).  
3. **Service-to-Service:** Các service giao tiếp nội bộ cũng thông qua API Gateway để đảm bảo tính nhất quán và log tập trung.

### **Danh sách các Services**

| Service Name | Port (Local) | Database | Công nghệ & Vai trò |
| :---- | :---- | :---- | :---- |
| **API Gateway** | 80 | N/A | **Nginx**. Cổng vào duy nhất, Load Balancing, Logging (JSON). |
| **Frontend Service** | 5173 | N/A | **Python (NiceGUI)**. Giao diện người dùng và quản trị viên. |
| **User Service** | 8000 | PostgreSQL | **FastAPI**. Quản lý User, đăng ký, thông tin cá nhân. |
| **Auth Service** | 8001 | Redis | **FastAPI**. Đăng nhập, cấp phát & xác thực JWT Token. |
| **Product Service** | 8002 | MySQL | **FastAPI**. Quản lý danh mục sản phẩm (Tên, giá, mô tả). |
| **Inventory Service** | 8003 | MySQL | **FastAPI**. Quản lý số lượng tồn kho. |
| **Cart Service** | 8004 | Redis | **FastAPI**. Quản lý giỏ hàng tạm thời (Thêm/Xóa/Sửa). |
| **Order Service** | 8005 | PostgreSQL | **FastAPI**. "Bộ não" xử lý đơn hàng, gọi các service khác để hoàn tất giao dịch. |
| **Payment Service** | 8006 | PostgreSQL | **FastAPI**. Giả lập cổng thanh toán và lưu lịch sử giao dịch. |

## **Công nghệ Sử dụng (Tech Stack)**

### **Backend**

* **Ngôn ngữ:** Python 3.10  
* **Framework:** FastAPI (High performance API)  
* **Communication:** HTTP REST (sử dụng thư viện httpx cho async calls)  
* **Authentication:** JWT (JSON Web Tokens), Passlib (Bcrypt hashing)

### **Frontend**

* **Framework:** NiceGUI (Dựa trên Vue.js & Quasar, nhưng viết bằng 100% Python)  
* **Styling:** Tailwind CSS (Tích hợp sẵn trong NiceGUI)

### **Databases**

* **PostgreSQL:** Dữ liệu quan hệ (Users, Orders, Payments).  
* **MySQL 8.0:** Dữ liệu sản phẩm và kho hàng (Products, Inventory).  
* **Redis:** Dữ liệu truy xuất nhanh (Tokens, Shopping Cart).

### **Infrastructure & DevOps**

* **Containerization:** Docker & Docker Compose.  
* **Gateway:** Nginx (Reverse Proxy).  
* **CI/CD:** GitHub Actions (Automated Linting & Building).

## **Tính năng Nổi bật**

### **1\. Phân quyền Người dùng (RBAC)**

Hệ thống hỗ trợ 3 vai trò với quyền hạn khác nhau:

* **USER (Khách hàng):** Xem sản phẩm, thêm vào giỏ, đặt hàng, xem hồ sơ.  
* **ADMIN (Quản trị viên):** Truy cập Dashboard, quản lý toàn bộ User, xóa sản phẩm.  
* **STAFF (Nhân viên):** Truy cập khu vực kho, nhập hàng, cập nhật số lượng tồn kho.

### **2\. Giao diện Frontend (NiceGUI)**

* **Landing Page:** Trang giới thiệu đẹp mắt.  
* **Product Grid:** Hiển thị sản phẩm dạng lưới responsive.  
* **Interactive Cart:** Giỏ hàng cập nhật thời gian thực (Real-time UI update).  
* **Admin Hub:** Trung tâm điều khiển dành riêng cho Admin/Staff.

### **3\. Quy trình Đặt hàng (Order Flow)**

Hệ thống xử lý logic phức tạp khi tạo đơn hàng:

1. Lấy thông tin Giỏ hàng & User.  
2. Kiểm tra giá mới nhất từ Product Service.  
3. Kiểm tra tồn kho từ Inventory Service.  
4. Thực hiện thanh toán qua Payment Service.  
5. Lưu đơn hàng \-\> Trừ kho \-\> Xóa giỏ hàng.

## **Cấu trúc Thư mục Dự án**

CapstoneProject/  
├── .github/workflows/   \# Cấu hình CI/CD  
├── infra/               \# Cấu hình hạ tầng (Nginx)  
├── logs\_data/           \# Thư mục chứa Log (JSON format) từ Gateway  
├── services/            \# Mã nguồn các microservices  
│   ├── auth-service/  
│   ├── cart-service/  
│   ├── frontend-service/ \# Code giao diện (NiceGUI)  
│   ├── inventory-service/  
│   ├── order-service/  
│   ├── payment-service/  
│   ├── product-service/  
│   └── user-service/  
├── docker-compose.yml   \# File khởi chạy toàn bộ hệ thống  
└── README.md            \# Tài liệu dự án

## **Hướng dẫn Cài đặt & Chạy**

### **Yêu cầu tiên quyết**

* Docker Desktop đã được cài đặt và đang chạy.  
* Git.

### **Các bước thực hiện**

1. **Clone repository:**  
   git clone \[https://github.com/hodaoty/CapstoneProject.git\](https://github.com/hodaoty/CapstoneProject.git)  
   cd CapstoneProject

2. Khởi chạy hệ thống:  
   Chạy lệnh sau tại thư mục gốc để build và start các containers:  
   docker-compose up \--build  
