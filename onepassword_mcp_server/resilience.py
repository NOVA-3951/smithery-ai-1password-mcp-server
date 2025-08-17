#!/usr/bin/env python3
"""
Resilience patterns for the 1Password MCP Server
Includes circuit breaker, retry logic, and timeout handling
"""

import asyncio
import time
import random
from typing import Any, Callable, Dict, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from contextlib import asynccontextmanager
import logging

logger = logging.getLogger(__name__)


class CircuitState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"        # Normal operation
    OPEN = "open"           # Failing, reject requests
    HALF_OPEN = "half_open" # Testing if service recovered


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker"""
    failure_threshold: int = 5          # Failures before opening
    recovery_timeout: int = 60          # Seconds before trying half-open
    success_threshold: int = 3          # Successes to close from half-open
    timeout: float = 30.0              # Request timeout in seconds


@dataclass
class CircuitBreakerStats:
    """Circuit breaker statistics"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    timeouts: int = 0
    circuit_open_count: int = 0
    last_failure_time: Optional[float] = None
    consecutive_failures: int = 0
    consecutive_successes: int = 0


class CircuitBreakerOpenError(Exception):
    """Raised when circuit breaker is open"""
    pass


class TimeoutError(Exception):
    """Raised when operation times out"""
    pass


class CircuitBreaker:
    """Circuit breaker implementation for 1Password API calls"""
    
    def __init__(self, config: CircuitBreakerConfig):
        self.config = config
        self.state = CircuitState.CLOSED
        self.stats = CircuitBreakerStats()
        self._lock = asyncio.Lock()
    
    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker protection"""
        async with self._lock:
            # Check if circuit should be opened
            if self.state == CircuitState.CLOSED and self._should_open():
                self._open_circuit()
            
            # Check if circuit should transition to half-open
            elif self.state == CircuitState.OPEN and self._should_attempt_reset():
                self._half_open_circuit()
            
            # Reject request if circuit is open
            if self.state == CircuitState.OPEN:
                self.stats.total_requests += 1
                logger.warning("Circuit breaker is OPEN, rejecting request")
                raise CircuitBreakerOpenError("Service is currently unavailable")
        
        # Execute the function with timeout
        try:
            self.stats.total_requests += 1
            result = await asyncio.wait_for(
                func(*args, **kwargs), 
                timeout=self.config.timeout
            )
            await self._on_success()
            return result
            
        except asyncio.TimeoutError:
            self.stats.timeouts += 1
            await self._on_failure()
            logger.error(f"Operation timed out after {self.config.timeout}s")
            raise TimeoutError(f"Operation timed out after {self.config.timeout}s")
            
        except Exception as e:
            await self._on_failure()
            raise
    
    async def _on_success(self):
        """Handle successful request"""
        async with self._lock:
            self.stats.successful_requests += 1
            self.stats.consecutive_failures = 0
            self.stats.consecutive_successes += 1
            
            # Close circuit if we're in half-open and have enough successes
            if (self.state == CircuitState.HALF_OPEN and 
                self.stats.consecutive_successes >= self.config.success_threshold):
                self._close_circuit()
    
    async def _on_failure(self):
        """Handle failed request"""
        async with self._lock:
            self.stats.failed_requests += 1
            self.stats.consecutive_failures += 1
            self.stats.consecutive_successes = 0
            self.stats.last_failure_time = time.time()
            
            # Open circuit if we have too many failures
            if self.state == CircuitState.HALF_OPEN or self._should_open():
                self._open_circuit()
    
    def _should_open(self) -> bool:
        """Check if circuit should be opened"""
        return self.stats.consecutive_failures >= self.config.failure_threshold
    
    def _should_attempt_reset(self) -> bool:
        """Check if we should attempt to reset circuit"""
        if self.stats.last_failure_time is None:
            return False
        return (time.time() - self.stats.last_failure_time) >= self.config.recovery_timeout
    
    def _open_circuit(self):
        """Open the circuit"""
        self.state = CircuitState.OPEN
        self.stats.circuit_open_count += 1
        logger.warning("Circuit breaker opened due to failures")
    
    def _half_open_circuit(self):
        """Set circuit to half-open"""
        self.state = CircuitState.HALF_OPEN
        self.stats.consecutive_successes = 0
        logger.info("Circuit breaker set to HALF_OPEN for testing")
    
    def _close_circuit(self):
        """Close the circuit"""
        self.state = CircuitState.CLOSED
        self.stats.consecutive_failures = 0
        logger.info("Circuit breaker closed - service recovered")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get circuit breaker statistics"""
        return {
            "state": self.state.value,
            "total_requests": self.stats.total_requests,
            "successful_requests": self.stats.successful_requests,
            "failed_requests": self.stats.failed_requests,
            "timeouts": self.stats.timeouts,
            "success_rate": (
                self.stats.successful_requests / max(self.stats.total_requests, 1) * 100
            ),
            "circuit_open_count": self.stats.circuit_open_count,
            "consecutive_failures": self.stats.consecutive_failures,
            "consecutive_successes": self.stats.consecutive_successes,
        }


@dataclass
class RetryConfig:
    """Configuration for retry logic"""
    max_attempts: int = 3
    base_delay: float = 1.0      # Base delay in seconds
    max_delay: float = 60.0      # Maximum delay in seconds
    exponential_base: float = 2.0 # Exponential backoff base
    jitter: bool = True          # Add random jitter


class RetryableError(Exception):
    """Base class for retryable errors"""
    pass


class NonRetryableError(Exception):
    """Base class for non-retryable errors"""
    pass


async def retry_with_backoff(
    func: Callable,
    config: RetryConfig,
    retryable_exceptions: Tuple = (Exception,),
    non_retryable_exceptions: Tuple = (),
    *args,
    **kwargs
) -> Any:
    """
    Retry function with exponential backoff and jitter
    
    Args:
        func: Function to retry
        config: Retry configuration
        retryable_exceptions: Exceptions that should trigger retry
        non_retryable_exceptions: Exceptions that should not trigger retry
        *args, **kwargs: Arguments for the function
        
    Returns:
        Result of successful function call
        
    Raises:
        Last exception if all retries fail
    """
    last_exception = None
    
    for attempt in range(config.max_attempts):
        try:
            result = await func(*args, **kwargs)
            if attempt > 0:
                logger.info(f"Function succeeded on attempt {attempt + 1}")
            return result
            
        except non_retryable_exceptions as e:
            logger.error(f"Non-retryable error on attempt {attempt + 1}: {e}")
            raise
            
        except retryable_exceptions as e:
            last_exception = e
            
            if attempt == config.max_attempts - 1:
                logger.error(f"All {config.max_attempts} attempts failed")
                break
            
            # Calculate delay with exponential backoff
            delay = min(
                config.base_delay * (config.exponential_base ** attempt),
                config.max_delay
            )
            
            # Add jitter to prevent thundering herd
            if config.jitter:
                delay = delay * (0.5 + random.random() * 0.5)
            
            logger.warning(
                f"Attempt {attempt + 1} failed: {e}. "
                f"Retrying in {delay:.2f}s"
            )
            
            await asyncio.sleep(delay)
    
    # All attempts failed
    if last_exception:
        raise last_exception
    else:
        raise Exception("All retry attempts failed with unknown error")


@asynccontextmanager
async def timeout_context(timeout_seconds: float):
    """Context manager for operation timeouts"""
    try:
        async with asyncio.timeout(timeout_seconds):
            yield
    except asyncio.TimeoutError:
        logger.error(f"Operation timed out after {timeout_seconds}s")
        raise TimeoutError(f"Operation timed out after {timeout_seconds}s")


class ResilientOperationManager:
    """Manager for resilient operations combining circuit breaker and retry logic"""
    
    def __init__(
        self,
        circuit_config: Optional[CircuitBreakerConfig] = None,
        retry_config: Optional[RetryConfig] = None
    ):
        self.circuit_breaker = CircuitBreaker(
            circuit_config or CircuitBreakerConfig()
        )
        self.retry_config = retry_config or RetryConfig()
    
    async def execute(
        self,
        func: Callable,
        retryable_exceptions: Tuple = (Exception,),
        non_retryable_exceptions: Tuple = (CircuitBreakerOpenError,),
        *args,
        **kwargs
    ) -> Any:
        """
        Execute function with both circuit breaker and retry logic
        
        Args:
            func: Function to execute
            retryable_exceptions: Exceptions that should trigger retry
            non_retryable_exceptions: Exceptions that should not trigger retry
            *args, **kwargs: Arguments for the function
            
        Returns:
            Result of successful function call
        """
        
        async def protected_func(*args, **kwargs):
            return await self.circuit_breaker.call(func, *args, **kwargs)
        
        return await retry_with_backoff(
            protected_func,
            self.retry_config,
            retryable_exceptions,
            non_retryable_exceptions,
            *args,
            **kwargs
        )
    
    def get_stats(self) -> Dict[str, Any]:
        """Get resilience statistics"""
        return {
            "circuit_breaker": self.circuit_breaker.get_stats(),
            "retry_config": {
                "max_attempts": self.retry_config.max_attempts,
                "base_delay": self.retry_config.base_delay,
                "max_delay": self.retry_config.max_delay,
            }
        }