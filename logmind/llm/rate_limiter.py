"""Rate limiter for LLM API calls to prevent abuse and cost overruns."""

import time
from collections import deque
from threading import Lock
from typing import Callable, TypeVar

T = TypeVar('T')


class RateLimiter:
    """
    Token bucket rate limiter for API calls.
    
    Prevents excessive API usage and cost overruns.
    """
    
    def __init__(
        self,
        max_calls: int = 60,
        time_window: float = 60.0,
        max_tokens_per_minute: int = 100000,
    ) -> None:
        """
        Initialize rate limiter.
        
        Args:
            max_calls: Maximum number of calls per time window
            time_window: Time window in seconds
            max_tokens_per_minute: Maximum tokens per minute (cost control)
        """
        self.max_calls = max_calls
        self.time_window = time_window
        self.max_tokens_per_minute = max_tokens_per_minute
        
        self._call_times: deque[float] = deque()
        self._token_usage: deque[tuple[float, int]] = deque()
        self._lock = Lock()
    
    def _clean_old_entries(self, current_time: float) -> None:
        """Remove entries outside the time window."""
        cutoff = current_time - self.time_window
        
        while self._call_times and self._call_times[0] < cutoff:
            self._call_times.popleft()
        
        while self._token_usage and self._token_usage[0][0] < cutoff:
            self._token_usage.popleft()
    
    def can_proceed(self) -> tuple[bool, str]:
        """
        Check if a call can proceed.
        
        Returns:
            Tuple of (can_proceed, reason_if_not)
        """
        with self._lock:
            current_time = time.time()
            self._clean_old_entries(current_time)
            
            if len(self._call_times) >= self.max_calls:
                wait_time = self.time_window - (current_time - self._call_times[0])
                return False, f"Rate limit exceeded. Wait {wait_time:.1f}s"
            
            total_tokens = sum(tokens for _, tokens in self._token_usage)
            if total_tokens >= self.max_tokens_per_minute:
                return False, f"Token limit exceeded ({total_tokens}/{self.max_tokens_per_minute})"
            
            return True, ""
    
    def record_call(self, tokens_used: int = 0) -> None:
        """Record a successful API call."""
        with self._lock:
            current_time = time.time()
            self._call_times.append(current_time)
            if tokens_used > 0:
                self._token_usage.append((current_time, tokens_used))
    
    def wait_if_needed(self, timeout: float = 60.0) -> bool:
        """
        Wait until a call can proceed.
        
        Args:
            timeout: Maximum time to wait in seconds
            
        Returns:
            True if can proceed, False if timeout
        """
        start_time = time.time()
        
        while True:
            can_proceed, reason = self.can_proceed()
            if can_proceed:
                return True
            
            if time.time() - start_time > timeout:
                return False
            
            time.sleep(0.5)
    
    def __call__(self, func: Callable[..., T]) -> Callable[..., T]:
        """Decorator to rate limit a function."""
        def wrapper(*args, **kwargs) -> T:
            if not self.wait_if_needed():
                raise RuntimeError("Rate limit timeout exceeded")
            
            result = func(*args, **kwargs)
            
            # Try to extract token usage from result
            tokens_used = 0
            if hasattr(result, 'input_tokens') and hasattr(result, 'output_tokens'):
                tokens_used = result.input_tokens + result.output_tokens
            
            self.record_call(tokens_used)
            return result
        
        return wrapper
    
    def get_stats(self) -> dict:
        """Get current rate limiter statistics."""
        with self._lock:
            current_time = time.time()
            self._clean_old_entries(current_time)
            
            total_tokens = sum(tokens for _, tokens in self._token_usage)
            
            return {
                "calls_in_window": len(self._call_times),
                "max_calls": self.max_calls,
                "tokens_in_window": total_tokens,
                "max_tokens": self.max_tokens_per_minute,
                "time_window": self.time_window,
            }

