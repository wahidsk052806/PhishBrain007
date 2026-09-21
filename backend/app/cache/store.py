"""Cache abstraction backed by Redis/Valkey with an in-memory fallback.

Never raises: any Redis connectivity issue silently downgrades to an
in-process dict-based cache so the rest of the app keeps working.
"""
from __future__ import annotations

import json
import time
from typing import Any, Optional

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class _InMemoryCache:
    def __init__(self) -> None:
        self._store: dict[str, tuple[float, str]] = {}

    def get(self, key: str) -> Optional[str]:
        item = self._store.get(key)
        if item is None:
            return None
        expires_at, value = item
        if expires_at and expires_at < time.time():
            self._store.pop(key, None)
            return None
        return value

    def set(self, key: str, value: str, ttl: int) -> None:
        expires_at = time.time() + ttl if ttl else 0
        self._store[key] = (expires_at, value)

    def delete(self, key: str) -> None:
        self._store.pop(key, None)

    def clear(self) -> None:
        self._store.clear()


class CacheStore:
    """Thin JSON-aware wrapper that prefers Redis but degrades gracefully."""

    def __init__(self) -> None:
        self._redis = None
        self._memory = _InMemoryCache()
        self._backend = "memory"
        self._try_connect()

    def _try_connect(self) -> None:
        settings = get_settings()
        try:
            import redis  # noqa: F401

            client = redis.Redis.from_url(settings.CACHE_URL, socket_connect_timeout=0.5, socket_timeout=0.5)
            client.ping()
            self._redis = client
            self._backend = "redis"
        except Exception as exc:  # noqa: BLE001
            logger.info("Cache backend falling back to in-memory store", extra={"extra_fields": {"error": str(exc)}})
            self._redis = None
            self._backend = "memory"

    @property
    def backend(self) -> str:
        return self._backend

    def get_json(self, key: str) -> Any:
        raw = self._get_raw(key)
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except Exception:  # noqa: BLE001
            return None

    def set_json(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        settings = get_settings()
        ttl = ttl if ttl is not None else settings.CACHE_TTL_SECONDS
        try:
            payload = json.dumps(value, default=str)
        except Exception:  # noqa: BLE001
            return
        self._set_raw(key, payload, ttl)

    def _get_raw(self, key: str) -> Optional[str]:
        if self._redis is not None:
            try:
                value = self._redis.get(key)
                return value.decode("utf-8") if isinstance(value, (bytes, bytearray)) else value
            except Exception as exc:  # noqa: BLE001
                logger.info("Redis get failed, falling back to memory", extra={"extra_fields": {"error": str(exc)}})
                self._redis = None
                self._backend = "memory"
        return self._memory.get(key)

    def _set_raw(self, key: str, value: str, ttl: int) -> None:
        if self._redis is not None:
            try:
                self._redis.set(key, value, ex=ttl or None)
                return
            except Exception as exc:  # noqa: BLE001
                logger.info("Redis set failed, falling back to memory", extra={"extra_fields": {"error": str(exc)}})
                self._redis = None
                self._backend = "memory"
        self._memory.set(key, value, ttl)

    def delete(self, key: str) -> None:
        if self._redis is not None:
            try:
                self._redis.delete(key)
            except Exception:  # noqa: BLE001
                pass
        self._memory.delete(key)

    def ping(self) -> bool:
        if self._redis is not None:
            try:
                return bool(self._redis.ping())
            except Exception:  # noqa: BLE001
                self._redis = None
                self._backend = "memory"
        return True


_cache_singleton: CacheStore | None = None


def get_cache() -> CacheStore:
    global _cache_singleton
    if _cache_singleton is None:
        _cache_singleton = CacheStore()
    return _cache_singleton
