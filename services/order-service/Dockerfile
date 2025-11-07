
FROM python:3.10-slim

WORKDIR /code

ENV PYTHONPATH=/code

COPY ./requirements.txt /code/requirements.txt
RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

COPY ./app /code/app

# Chạy app trên port 8005
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8005"]