import time
import os
import json
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Set

@dataclass
class AppealRequest:
    id: str
    ip: str
    reason: str
    timestamp: float
    status: str = "pending"  # "pending", "approved", "rejected"

@dataclass
class BlockRecord:
    ip: str
    reason: str
    expiry: float

class WhitelistManager:
    """Manages a set of whitelisted IPs that bypass all security checks."""
    def __init__(self, redis_client=None):
        self._redis = redis_client
        self._in_memory: Set[str] = set()
        self._prefix = "whitelist:"

    def add(self, ip: str):
        if self._redis:
            self._redis.sadd(self._prefix, ip)
        else:
            self._in_memory.add(ip)

    def remove(self, ip: str):
        if self._redis:
            self._redis.srem(self._prefix, ip)
        else:
            self._in_memory.discard(ip)

    def is_whitelisted(self, ip: str) -> bool:
        if self._redis:
            return self._redis.sismember(self._prefix, ip)
        return ip in self._in_memory

class AppealStore:
    """Stores and retrieves appeal requests."""
    def __init__(self, redis_client=None):
        self._redis = redis_client
        self._in_memory: Dict[str, AppealRequest] = {}
        self._prefix = "appeal:"

    def submit(self, appeal: AppealRequest):
        if self._redis:
            self._redis.set(f"{self._prefix}{appeal.id}", json.dumps(asdict(appeal)))
        else:
            self._in_memory[appeal.id] = appeal

    def get(self, appeal_id: str) -> Optional[AppealRequest]:
        if self._redis:
            data = self._redis.get(f"{self._prefix}{appeal_id}")
            if data:
                return AppealRequest(**json.loads(data))
            return None
        return self._in_memory.get(appeal_id)

    def update_status(self, appeal_id: str, status: str):
        appeal = self.get(appeal_id)
        if appeal:
            appeal.status = status
            self.submit(appeal)

class BlockRegistry:
    """Tracks active blocks with TTL (auto-expiry)."""
    def __init__(self, redis_client=None):
        self._redis = redis_client
        # In-memory storage: {ip: BlockRecord}
        self._in_memory: Dict[str, BlockRecord] = {}
        self._prefix = "block:"

    def block(self, ip: str, reason: str, ttl_sec: float = 3600):
        expiry = time.time() + ttl_sec
        record = BlockRecord(ip=ip, reason=reason, expiry=expiry)
        
        if self._redis:
            self._redis.setex(f"{self._prefix}{ip}", int(ttl_sec), json.dumps(asdict(record)))
        else:
            self._in_memory[ip] = record

    def is_blocked(self, ip: str) -> bool:
        now = time.time()
        if self._redis:
            data = self._redis.get(f"{self._prefix}{ip}")
            return data is not None
        
        record = self._in_memory.get(ip)
        if record:
            if record.expiry > now:
                return True
            else:
                del self._in_memory[ip]
        return False

# Global instances initialized in main.py based on Redis config
whitelist_manager = WhitelistManager()
appeal_store = AppealStore()
block_registry = BlockRegistry()
