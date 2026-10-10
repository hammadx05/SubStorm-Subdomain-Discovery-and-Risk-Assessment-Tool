"""
Rate limiter for API calls to respect service limits
"""
import time
import threading
from collections import deque
from typing import Callable

class RateLimiter:
    """Thread-safe rate limiter using token bucket algorithm"""
    
    def __init__(self, max_requests: int, time_window: int):
        """
        Args:
            max_requests: Maximum number of requests in time_window
            time_window: Time window in seconds
        """
        self.max_requests = max_requests
        self.time_window = time_window
        self.tokens = max_requests
        self.last_refill = time.time()
        self.lock = threading.Lock()
    
    def acquire(self, blocking: bool = True) -> bool:
        """
        Acquire a token for making a request
        Returns True if token acquired, False if rate limited
        """
        with self.lock:
            self._refill_tokens()
            
            if self.tokens >= 1:
                self.tokens -= 1
                return True
            elif blocking:
                # Wait for next token
                wait_time = self.time_window / self.max_requests
                time.sleep(wait_time)
                return self.acquire(blocking=False)
            else:
                return False
    
    def _refill_tokens(self):
        """Refill tokens based on elapsed time"""
        now = time.time()
        elapsed = now - self.last_refill
        if elapsed >= self.time_window:
            self.tokens = self.max_requests
            self.last_refill = now
        else:
            new_tokens = int(elapsed / self.time_window * self.max_requests)
            if new_tokens > 0:
                self.tokens = min(self.max_requests, self.tokens + new_tokens)
                self.last_refill = now
