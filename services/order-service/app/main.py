import logging
import time
from fastapi import FastAPI, Request
from app.api.v1 import orders
from app.db.database import Base, engine

# --- 1. LOGGING CONFIGURATION ---
# Create a custom logger with request_id in the format
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | [%(request_id)s] | %(message)s'
)
logger = logging.getLogger(__name__)

# Create tables for "orders" and "order_items"
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Order Service")

# --- 2. TRACE AND SAMPLE MIDDLEWARE ---
@app.middleware("http")
async def trace_and_sample_middleware(request: Request, call_next):
    # Extract headers passed from Nginx (API Gateway)
    request_id = request.headers.get("X-Request-ID", "no-request-id")
    sampling_flag = request.headers.get("X-Sampling-Flag", "0")
    user_id_hash = request.headers.get("X-User-Id-Hash", "unknown")
    
    # Inject request_id into logger for subsequent log lines
    old_factory = logging.getLogRecordFactory()

    def record_factory(*args, **kwargs):
        record = old_factory(*args, **kwargs)
        record.request_id = request_id
        return record

    logging.setLogRecordFactory(record_factory)

    start_time = time.time()
    
    # --- SAMPLING LOGIC (IF FLAG IS 1) ---
    if sampling_flag == "1":
        # Nginx flagged this request -> read and log the full body
        body_bytes = await request.body()
        logger.warning(f"SAMPLING TRIGGERED: Suspicious request from UserHash: {user_id_hash}")
        logger.warning(f"PAYLOAD ATTACHED: {body_bytes.decode('utf-8')}")
        
        # Restore the body state so the actual endpoint can read it without hanging
        async def receive():
            return {"type": "http.request", "body": body_bytes}
        request._receive = receive

    # Process the actual request
    response = await call_next(request)
    
    process_time = (time.time() - start_time) * 1000
    
    # Log basic application-level information
    logger.info(f"Processed {request.method} {request.url.path} - Time: {process_time:.2f}ms - Status: {response.status_code}")

    # Return X-Request-ID to the client for tracing/debugging
    response.headers["X-Request-ID"] = request_id
    
    # Restore the old factory to maintain thread safety
    logging.setLogRecordFactory(old_factory)
    
    return response

# --- 3. ROUTER REGISTRATION ---
app.include_router(orders.router, prefix="/api", tags=["orders"])

@app.get("/")
def read_root():
    """Healthcheck Endpoint"""
    return {"service": "Order Service is running"}