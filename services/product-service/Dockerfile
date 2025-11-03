# Use official Python slim image
FROM python:3.11-slim

# Set working directory
WORKDIR /code

# Copy requirements and install
COPY ./requirements.txt /code/requirements.txt

# Install system dependencies and Python packages
RUN apt-get update && apt-get install -y \
        build-essential \
        libssl-dev \
        libffi-dev \
        python3-dev \
    && pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir --upgrade -r /code/requirements.txt cryptography \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy application code
COPY ./app /code/app

# Expose the port Uvicorn will run on
EXPOSE 8002

# Run the FastAPI app with Uvicorn
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8002"]
