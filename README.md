# **Dự án E-commerce Microservices (Capstone Project)**

Copyright: tykhoihanhduyen 

Đây là một dự án backend E-commerce hoàn chỉnh, được xây dựng theo kiến trúc microservice. Hệ thống bao gồm 7 service độc lập (viết bằng FastAPI), 1 API Gateway (Nginx), và 3 loại cơ sở dữ liệu (PostgreSQL, MySQL, Redis) để xử lý các nghiệp vụ khác nhau.

Toàn bộ hệ thống được container hóa bằng Docker và quản lý bởi Docker Compose.

## **Kiến trúc hệ thống**

Hệ thống được thiết kế với một cổng vào duy nhất (`api-gateway`) chịu trách nhiệm định tuyến (routing) các yêu cầu đến các service vi mô (microservice) tương ứng.

### **Sơ đồ các thành phần (Components)**

1. **API Gateway (Nginx):**  
   * Chạy trên `http://localhost:80`.  
   * Là cổng vào duy nhất cho tất cả các request.  
   * Định tuyến các đường dẫn (ví dụ: `/api/users/*`) đến service nội bộ tương ứng (ví dụ: `user-service:8000`).  
2. **User Service (FastAPI & PostgreSQL):**  
   * Cổng nội bộ: `8000`.  
   * **Trách nhiệm:** Quản lý CRUD (Tạo, Đọc, Cập nhật, Xóa) thông tin người dùng, địa chỉ, và mật khẩu đã băm.  
   * CSDL: `postgres-db` (Dùng chung với Order & Payment Service).  
3. **Auth Service (FastAPI & Redis):**  
   * Cổng nội bộ: `8001`.  
   * **Trách nhiệm:** Xử lý đăng nhập (`/login`), xác thực mật khẩu (bằng cách gọi `user-service`), tạo JWT (Access Token & Refresh Token), và lưu Refresh Token vào Redis.  
   * CSDL: `redis-db` (Dùng chung với Cart Service).  
4. **Product Service (FastAPI & MySQL):**  
   * Cổng nội bộ: `8002`.  
   * **Trách nhiệm:** Quản lý danh mục sản phẩm (tên, mô tả, giá, danh mục).  
   * CSDL: `mysql-db` (Dùng chung với Inventory Service).  
5. **Inventory Service (FastAPI & MySQL):**  
   * Cổng nội bộ: `8003`.  
   * **Trách nhiệm:** Chỉ quản lý số lượng tồn kho (`product_id` \-\> `quantity`). Cung cấp API để tăng/giảm số lượng.  
   * CSDL: `mysql-db` (Dùng chung với Product Service, nhưng làm việc trên bảng `inventory`).  
6. **Cart Service (FastAPI & Redis):**  
   * Cổng nội bộ: `8004`.  
   * **Trách nhiệm:** Quản lý giỏ hàng tạm thời của người dùng (sử dụng Redis Hash, ví dụ: `cart:<user_id>`).  
   * CSDL: `redis-db` (Dùng chung với Auth Service).  
7. **Order Service (FastAPI & PostgreSQL):**  
   * Cổng nội bộ: `8005`.  
   * **Trách nhiệm:** "Bộ não" của hệ thống. Đây là service điều phối (orchestrator) chính, chịu trách nhiệm thực hiện toàn bộ luồng nghiệp vụ "Tạo Đơn hàng".  
   * CSDL: `postgres-db` (Tạo bảng `orders` và `order_items`).  
8. **Payment Service (FastAPI & PostgreSQL):**  
   * Cổng nội bộ: `8006`.  
   * **Trách nhiệm:** Xử lý logic thanh toán. Hiện tại đang "giả lập" (mock) một giao dịch thành công và ghi log vào bảng `payments`.  
   * CSDL: `postgres-db` (Tạo bảng `payments`).

### **Mạng (Networking)**

Tất cả 11 container (7 service, 3 DB, 1 Gateway) đều được kết nối vào một mạng ảo (bridge network) tùy chỉnh tên là `ecommerce-net`. Điều này cho phép các service gọi nhau nội bộ một cách an toàn bằng tên service (ví dụ: `http://user-service:8000`).

## **Công nghệ sử dụng**

* **Backend:** Python 3.10, FastAPI  
* **Database:**  
  * PostgreSQL (Cho dữ liệu quan hệ, user, đơn hàng)  
  * MySQL 8.0 (Cho dữ liệu sản phẩm, kho hàng)  
  * Redis (Cho dữ liệu cache, session, giỏ hàng)  
* **API Gateway:** Nginx  
* **Containerization:** Docker & Docker Compose  
* **Thư viện Python (chính):**  
  * `SQLAlchemy` (ORM cho SQL)  
  * `httpx` (Cho giao tiếp service-to-service bất đồng bộ)  
  * `redis-py` (Client cho Redis)  
  * `passlib[bcrypt]` (Băm mật khẩu)  
  * `python-jose[cryptography]` (Tạo JWT)

## **Khởi chạy Dự án**

### **Yêu cầu**

* Docker  
* Docker Compose

### **Các bước**

1. Clone repository này:  
git clone \[https://github.com/hodaoty/CapstoneProject.git\](https://github.com/hodaoty/CapstoneProject.git)  
cd CapstoneProject

   
2. Đảm bảo tất cả các file `__init__.py` (rỗng) đã được tạo trong các thư mục con của mỗi service (ví dụ: `services/user-service/app/core/`, `services/user-service/app/db/`...)

Build và khởi chạy toàn bộ 11 container:  
docker-compose up \--build

3. (Thêm `-d` để chạy ở chế độ nền)  
4. Hệ thống đã sẵn sàng\! Tất cả các API đều có thể được truy cập thông qua API Gateway tại: `http://localhost`

## **API Workflow (Luồng Test chính)**

Đây là quy trình test End-to-End (từ đầu đến cuối) bằng Postman.

### **Giai đoạn 1: Chuẩn bị**

1. **Tạo User:** `POST http://localhost/api/users/` (Body: `{"email": "user@test.com", "password": "123"}`)  
2. **Tạo Sản phẩm:** `POST http://localhost/api/products/` (Body: `{"name": "Laptop", "price": 1000}`) (Giả sử trả về `id: 1`)  
3. **Thêm Kho:** `POST http://localhost/api/inventory/update` (Body: `{"product_id": 1, "change_quantity": 10}`)  
4. **Thêm vào Giỏ hàng:** `POST http://localhost/api/cart/user@test.com` (Body: `{"product_id": 1, "quantity": 2}`)

### **Giai đoạn 2: Đặt hàng (Test lớn)**

5. **Tạo Đơn hàng:** `POST http://localhost/api/orders/` (Body: `{"user_id": "user@test.com"}`)

### **Giai đoạn 3: Kiểm tra**

6. **Kiểm tra Kho:** `GET http://localhost/api/inventory/1` (Số lượng phải còn 8\)  
7. **Kiểm tra Giỏ hàng:** `GET http://localhost/api/cart/user@test.com` (Giỏ hàng phải `items: []`)  
8. **Kiểm tra CSDL (Tùy chọn):**  
   * Kết nối **PostgreSQL** (`localhost:5432`): Kiểm tra bảng `orders`, `order_items`, `payments` đã có dữ liệu mới.  
   * Kết nối **Redis** (`localhost:6379`): Chạy `HGETALL cart:user@test.com` (phải trả về rỗng).

