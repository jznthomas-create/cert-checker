import os, time, threading
from collections import defaultdict, deque

class RateLimiter:
    """按 IP 的滑动窗口限流（单进程内存版；多实例需换 Redis）。"""
    def __init__(self, limit=None, window=60):
        self.limit = int(limit or os.getenv("RATE_LIMIT_PER_MIN", "20")); self.window = window
        self.hits = defaultdict(deque); self.lock = threading.Lock()
    def allow(self, key: str):
        now = time.monotonic()
        with self.lock:
            q = self.hits[key]
            while q and q[0] <= now - self.window: q.popleft()
            if len(q) >= self.limit: return False, int(q[0] + self.window - now) + 1
            q.append(now); return True, 0
