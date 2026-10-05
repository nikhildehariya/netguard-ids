import sys
import os
import time
import json
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from config import (
    REDIS_HOST, REDIS_PORT, REDIS_PASSWORD, REDIS_STREAM_KEY,
    REDIS_CONSUMER_GROUP, USE_REDIS_BUFFER
)
from predict import detector
from alert import handle_alert

try:
    import redis
    REDIS_INSTALLED = True
except ImportError:
    REDIS_INSTALLED = False


class FlowStreamConsumer:
    """
    Redis Stream Consumer Group Worker for NetGuard IDS.
    Reads flow feature batches from Redis Stream, runs XGBoost inference in batches,
    triggers alerts/DB persistence, and acknowledges processed messages.
    """
    def __init__(self, consumer_name: str = None):
        self.consumer_name = consumer_name or f"worker-{os.getpid()}-{threading.get_ident()}"
        self.running = False
        self.client = None
        self._thread = None

    def _connect(self) -> bool:
        if not (USE_REDIS_BUFFER and REDIS_INSTALLED):
            return False
        try:
            self.client = redis.Redis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                password=REDIS_PASSWORD if REDIS_PASSWORD else None,
                decode_responses=True,
                socket_connect_timeout=0.3,
                socket_timeout=0.3
            )
            self.client.ping()

            # Ensure consumer group exists
            try:
                self.client.xgroup_create(
                    name=REDIS_STREAM_KEY,
                    groupname=REDIS_CONSUMER_GROUP,
                    id="$",
                    mkstream=True
                )
                print(f"[consumer] Created consumer group '{REDIS_CONSUMER_GROUP}' on stream '{REDIS_STREAM_KEY}'")
            except redis.exceptions.ResponseError as e:
                if "BUSYGROUP" in str(e):
                    pass  # Group already exists
                else:
                    raise e
            return True
        except Exception as e:
            print(f"[consumer] Failed to connect to Redis: {e}")
            self.client = None
            return False

    def process_batch(self, messages: list) -> int:
        """
        Processes a list of stream messages [(msg_id, data_dict), ...].
        Returns count of successfully processed records.
        """
        if not messages:
            return 0

        msg_ids = []
        records = []
        source_ips = []

        for msg_id, data in messages:
            try:
                payload_str = data.get("payload")
                if not payload_str:
                    msg_ids.append(msg_id)
                    continue

                feature_dict = json.loads(payload_str)
                src_ip = feature_dict.get("source_ip", "unknown")
                
                records.append(feature_dict)
                source_ips.append(src_ip)
                msg_ids.append(msg_id)
            except Exception as parse_err:
                print(f"[consumer] Record parse error: {parse_err}")
                msg_ids.append(msg_id)

        if not records:
            if msg_ids:
                self.client.xack(REDIS_STREAM_KEY, REDIS_CONSUMER_GROUP, *msg_ids)
            return 0

        # Perform predictions & alerts
        try:
            # Load model if not loaded
            if not detector._loaded:
                detector.load()

            for record, src_ip in zip(records, source_ips):
                result = detector.predict(record)
                handle_alert(result, source_ip=src_ip, flow_id="", test_mode=False)

            # Acknowledge messages in Redis
            self.client.xack(REDIS_STREAM_KEY, REDIS_CONSUMER_GROUP, *msg_ids)
            return len(records)
        except Exception as e:
            print(f"[consumer] Batch prediction processing error: {e}")
            return 0

    def start(self, run_in_background: bool = True):
        """Starts the consumer worker thread/loop."""
        self.running = True
        if run_in_background:
            self._thread = threading.Thread(target=self._run_loop, daemon=True)
            self._thread.start()
            print(f"[consumer] Background worker started ({self.consumer_name})")
        else:
            self._run_loop()

    def stop(self):
        """Stops the consumer worker cleanly."""
        self.running = False
        print(f"[consumer] Stopping worker ({self.consumer_name})...")

    def _run_loop(self):
        while self.running:
            if not self.client:
                if not self._connect():
                    time.sleep(3)
                    continue

            try:
                # Read new messages from group (batch up to 100, wait max 1000ms)
                entries = self.client.xreadgroup(
                    groupname=REDIS_CONSUMER_GROUP,
                    consumername=self.consumer_name,
                    streams={REDIS_STREAM_KEY: ">"},
                    count=100,
                    block=1000
                )

                if entries:
                    for stream_name, stream_messages in entries:
                        count = self.process_batch(stream_messages)
                        if count > 0:
                            print(f"[consumer] Processed batch of {count} flows from Redis Stream.")

            except redis.exceptions.ConnectionError:
                print("[consumer] Connection lost to Redis. Retrying...")
                self.client = None
                time.sleep(2)
            except Exception as e:
                print(f"[consumer] Error in stream loop: {e}")
                time.sleep(1)


consumer_worker = FlowStreamConsumer()


if __name__ == "__main__":
    print("[consumer] Starting NetGuard Redis Stream Consumer Service...")
    worker = FlowStreamConsumer()
    worker.start(run_in_background=False)
