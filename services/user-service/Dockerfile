# Sử dụng base image Python
FROM python:3.10-slim

# Thiết lập thư mục làm việc
WORKDIR /code

# Copy file requirements và cài đặt
COPY ./requirements.txt /code/requirements.txt
RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

# Copy toàn bộ code vào
COPY ./app /code/app

# Chạy ứng dụng
# 0.0.0.0 để lắng nghe trên tất cả các IP
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]