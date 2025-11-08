import redis
from app.core.config import settings

redis_client = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)


def get_redis_db():
    try:
        yield redis_client
    finally:
        pass
