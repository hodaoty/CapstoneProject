import redis
from app.core.config import settings

# Khởi tạo một "connection pool" tới Redis
# decode_responses=True giúp chúng ta nhận về string (thay vì bytes)
redis_client = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)


def get_redis_db():
    try:
        yield redis_client
    finally:
        # Với Redis, chúng ta không cần 'close()' kết nối
        # vì 'redis-py' tự quản lý connection pool.
        pass
