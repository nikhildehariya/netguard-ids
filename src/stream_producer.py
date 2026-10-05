import sys
import json
import requests
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from config import (
    REDIS_HOST, REDIS_PORT, REDIS_PASSWORD, REDIS_STREAM_KEY,
    USE_REDIS_BUFFER, API_URL, AGENT_SECRET_KEY
)

try:
    import redis
    REDIS_INSTALLED = True
except ImportError:
    REDIS_INSTALLED = False


import time


class FlowStreamProducer:
    """
    Redis Stream Producer with Automatic Fallback.
    Publishes packet flow features into Redis Stream (netguard:flow_stream) to handle high burst traffic.
    If Redis is unavailable or unconfigured, falls back to direct HTTP POST requests.
    """
    def __init__(self):
        self._client = None
        self._connected = False
        self._last_check = 0
        self._check_cooldown = 5  # Check Redis connection at most every 5s if offline
        self._check_connection()

    def _check_connection(self):
        now = time.time()
        if not (USE_REDIS_BUFFER and REDIS_INSTALLED):
            self._connected = False
            return
        if not self._connected and (now - self._last_check) < self._check_cooldown:
            return
        self._last_check = now
        try:
            self._client = redis.Redis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                password=REDIS_PASSWORD if REDIS_PASSWORD else None,
                socket_connect_timeout=0.3,
                socket_timeout=0.3,
                decode_responses=True
            )
            self._client.ping()
            self._connected = True
            print(f"[producer] Connected to Redis Stream at {REDIS_HOST}:{REDIS_PORT}")
        except Exception:
            self._connected = False
            self._client = None

    def is_available(self) -> bool:
        if not self._connected:
            self._check_connection()
        return self._connected

    def publish_flow(self, features: dict) -> bool:
        """
        Publishes flow features dictionary to Redis Stream.
        Returns True if successfully pushed to Redis, False if fallback is required.
        """
        if not self.is_available():
            return False

        try:
            # Serialize features dict to JSON payload
            payload = json.dumps(features)
            self._client.xadd(
                REDIS_STREAM_KEY,
                {"payload": payload},
                maxlen=50000,
                approximate=True
            )
            return True
        except Exception as e:
            print(f"[producer] Redis XADD error: {e}. Switching to HTTP fallback.")
            self._connected = False
            return False


producer = FlowStreamProducer()


def dispatch_flow(features: dict):
    """
    Dispatches a flow record.
    Attempts Redis Stream publishing first; if unavailable, uses direct HTTP API fallback.
    """
    if producer.publish_flow(features):
        return

    # Direct HTTP Fallback
    try:
        requests.post(
            f"{API_URL}/predict",
            json=features,
            headers={"X-Agent-Key": AGENT_SECRET_KEY},
            timeout=2
        )
    except requests.exceptions.ConnectionError:
        pass
    except Exception as e:
        print(f"[capture] HTTP API error: {e}")
