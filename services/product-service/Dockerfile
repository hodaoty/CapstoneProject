# Use official Python slim image
FROM python:3.10-slim

# Set working directory
WORKDIR /code
ENV PYTHONPATH=/code
# Copy requirements and install
COPY ./requirements.txt /code/requirements.txt

# Install system dependencies and Python packages
RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

# Copy application code
COPY ./app /code/app

# Expose the port Uvicorn will run on
#EXPOSE 8002

# Run the FastAPI app with Uvicorn
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8002"]
