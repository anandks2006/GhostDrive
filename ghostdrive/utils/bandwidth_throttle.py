"""
bandwidth_throttle.py -- Token bucket rate limiter for upload and download bandwidth control.
"""

import asyncio
import time
import logging
from typing import AsyncGenerator

logger = logging.getLogger(__name__)

class TokenBucketLimiter:
    """Token bucket rate limiter for controlling throughput (bytes/sec)."""
    def __init__(self, rate_limit: int = 0) -> None:
        self.rate_limit = rate_limit  # bytes per second. 0 = unlimited
        self.capacity = max(rate_limit, 64 * 1024)
        self.tokens = self.capacity
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()
        
    def set_rate_limit(self, rate_limit: int) -> None:
        self.rate_limit = rate_limit
        self.capacity = max(rate_limit, 64 * 1024)
        self.tokens = min(self.tokens, self.capacity)
        
    async def consume(self, amount: int) -> None:
        if self.rate_limit <= 0:
            return
            
        async with self._lock:
            while amount > 0:
                now = time.monotonic()
                elapsed = now - self.last_update
                self.last_update = now
                
                # Add new tokens
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rate_limit)
                
                if self.tokens >= amount:
                    self.tokens -= amount
                    break
                else:
                    # Consume whatever tokens exist
                    amount -= int(self.tokens)
                    self.tokens = 0
                    # Sleep until more tokens are generated
                    wait_time = amount / self.rate_limit
                    await asyncio.sleep(min(wait_time, 0.1))

# Global rate limiters
UPLOAD_LIMITER = TokenBucketLimiter(0)
DOWNLOAD_LIMITER = TokenBucketLimiter(0)

async def throttle_generator(gen: AsyncGenerator[bytes, None], limiter: TokenBucketLimiter) -> AsyncGenerator[bytes, None]:
    """Wraps an async bytes generator to apply rate limiting."""
    async for chunk in gen:
        await limiter.consume(len(chunk))
        yield chunk
