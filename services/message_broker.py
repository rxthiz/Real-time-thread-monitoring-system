import asyncio
import os
from dataclasses import dataclass
from typing import Optional

import redis.asyncio as redis


@dataclass
class BrokerSettings:
    backend: str = os.getenv("ALERT_BROKER_BACKEND", "redis").strip().lower()
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    queue_name: str = os.getenv("ALERT_QUEUE_KEY", "alerts:queue")
    dlq_name: str = os.getenv("ALERT_DLQ_KEY", "alerts:dlq")
    kafka_bootstrap_servers: str = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    rabbitmq_url: str = os.getenv("RABBITMQ_URL", "amqp://guest:guest@localhost/")


class AlertMessageBroker:
    """
    Queue abstraction with pluggable backends.

    Supported backends:
    - redis (default)
    - rabbitmq (requires aio-pika)
    - kafka (requires aiokafka)
    """

    def __init__(self, settings: Optional[BrokerSettings] = None) -> None:
        self.cfg = settings or BrokerSettings()
        self._redis_client: Optional[redis.Redis] = None
        self._rabbit_conn = None
        self._rabbit_channel = None
        self._kafka_producer = None
        self._kafka_consumer = None

    async def _ensure_redis(self) -> redis.Redis:
        if self._redis_client is None:
            self._redis_client = redis.from_url(self.cfg.redis_url, decode_responses=True)
        return self._redis_client

    async def _ensure_rabbit(self):
        if self._rabbit_channel is not None:
            return self._rabbit_channel
        try:
            import aio_pika
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError(
                "RabbitMQ backend requires aio-pika. Install with: pip install aio-pika"
            ) from exc

        self._rabbit_conn = await aio_pika.connect_robust(self.cfg.rabbitmq_url)
        self._rabbit_channel = await self._rabbit_conn.channel()
        await self._rabbit_channel.declare_queue(self.cfg.queue_name, durable=True)
        await self._rabbit_channel.declare_queue(self.cfg.dlq_name, durable=True)
        return self._rabbit_channel

    async def _ensure_kafka_producer(self):
        if self._kafka_producer is not None:
            return self._kafka_producer
        try:
            from aiokafka import AIOKafkaProducer
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError(
                "Kafka backend requires aiokafka. Install with: pip install aiokafka"
            ) from exc

        producer = AIOKafkaProducer(bootstrap_servers=self.cfg.kafka_bootstrap_servers)
        await producer.start()
        self._kafka_producer = producer
        return producer

    async def _ensure_kafka_consumer(self):
        if self._kafka_consumer is not None:
            return self._kafka_consumer
        try:
            from aiokafka import AIOKafkaConsumer
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError(
                "Kafka backend requires aiokafka. Install with: pip install aiokafka"
            ) from exc

        consumer = AIOKafkaConsumer(
            self.cfg.queue_name,
            bootstrap_servers=self.cfg.kafka_bootstrap_servers,
            auto_offset_reset="latest",
            enable_auto_commit=True,
            group_id=os.getenv("KAFKA_ALERT_CONSUMER_GROUP", "threat-alert-worker"),
        )
        await consumer.start()
        self._kafka_consumer = consumer
        return consumer

    async def publish_queue(self, message: str) -> None:
        backend = self.cfg.backend
        if backend == "redis":
            client = await self._ensure_redis()
            await client.lpush(self.cfg.queue_name, message)
            return
        if backend == "rabbitmq":
            import aio_pika

            channel = await self._ensure_rabbit()
            await channel.default_exchange.publish(
                aio_pika.Message(body=message.encode("utf-8"), delivery_mode=aio_pika.DeliveryMode.PERSISTENT),
                routing_key=self.cfg.queue_name,
            )
            return
        if backend == "kafka":
            producer = await self._ensure_kafka_producer()
            await producer.send_and_wait(self.cfg.queue_name, message.encode("utf-8"))
            return
        raise ValueError(f"Unsupported ALERT_BROKER_BACKEND '{backend}'")

    async def publish_dlq(self, message: str) -> None:
        backend = self.cfg.backend
        if backend == "redis":
            client = await self._ensure_redis()
            await client.lpush(self.cfg.dlq_name, message)
            return
        if backend == "rabbitmq":
            import aio_pika

            channel = await self._ensure_rabbit()
            await channel.default_exchange.publish(
                aio_pika.Message(body=message.encode("utf-8"), delivery_mode=aio_pika.DeliveryMode.PERSISTENT),
                routing_key=self.cfg.dlq_name,
            )
            return
        if backend == "kafka":
            producer = await self._ensure_kafka_producer()
            await producer.send_and_wait(self.cfg.dlq_name, message.encode("utf-8"))
            return
        raise ValueError(f"Unsupported ALERT_BROKER_BACKEND '{backend}'")

    async def consume_queue(self, timeout: int = 5) -> Optional[str]:
        backend = self.cfg.backend
        if backend == "redis":
            client = await self._ensure_redis()
            item = await client.brpop(self.cfg.queue_name, timeout=timeout)
            if not item:
                return None
            _, payload = item
            return payload
        if backend == "rabbitmq":
            channel = await self._ensure_rabbit()
            queue = await channel.declare_queue(self.cfg.queue_name, durable=True)
            message = await queue.get(timeout=timeout, fail=False)
            if message is None:
                return None
            async with message.process():
                return message.body.decode("utf-8")
        if backend == "kafka":
            consumer = await self._ensure_kafka_consumer()
            try:
                record = await asyncio.wait_for(consumer.getone(), timeout=float(timeout))
            except asyncio.TimeoutError:
                return None
            return record.value.decode("utf-8")
        raise ValueError(f"Unsupported ALERT_BROKER_BACKEND '{backend}'")

    async def queue_length(self) -> Optional[int]:
        if self.cfg.backend == "redis":
            client = await self._ensure_redis()
            return int(await client.llen(self.cfg.queue_name))
        return None

    async def dlq_length(self) -> Optional[int]:
        if self.cfg.backend == "redis":
            client = await self._ensure_redis()
            return int(await client.llen(self.cfg.dlq_name))
        return None

    async def close(self) -> None:
        if self._redis_client is not None:
            await self._redis_client.aclose()
            self._redis_client = None
        if self._kafka_consumer is not None:
            await self._kafka_consumer.stop()
            self._kafka_consumer = None
        if self._kafka_producer is not None:
            await self._kafka_producer.stop()
            self._kafka_producer = None
        if self._rabbit_conn is not None:
            await self._rabbit_conn.close()
            self._rabbit_conn = None
            self._rabbit_channel = None
