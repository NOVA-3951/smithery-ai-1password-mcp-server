#!/usr/bin/env python3
"""
Test script for P1 Error Handling, Resilience & Monitoring features
Validates all enhanced functionality of the 1Password MCP Server
"""

import asyncio
import os
import json
import time
from typing import Dict, Any
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

# Set test environment variables
os.environ.update({
    "OP_SERVICE_ACCOUNT_TOKEN": "ops_test_token_12345678901234567890",
    "ENVIRONMENT": "development",
    "LOG_LEVEL": "DEBUG",
    "RATE_LIMIT_MAX_REQUESTS": "5",
    "RATE_LIMIT_WINDOW_SECONDS": "10",
    "CIRCUIT_BREAKER_FAILURE_THRESHOLD": "3",
    "RETRY_MAX_ATTEMPTS": "2"
})

# Import our modules after setting environment
from config import ConfigLoader, ServerConfig
from structured_logging import get_logger, CorrelationContext, SensitiveDataScrubber
from resilience import CircuitBreaker, CircuitBreakerConfig, retry_with_backoff, RetryConfig
from monitoring import MetricsCollector, HealthChecker, basic_health_check


class TestP1Features(unittest.TestCase):
    """Test suite for P1 enhancements"""
    
    def setUp(self):
        """Set up test environment"""
        self.config = ConfigLoader.load_from_environment()
        self.logger = get_logger("test")
        self.metrics_collector = MetricsCollector()
    
    def test_configuration_loading(self):
        """Test configuration loading and validation"""
        print("\n🔧 Testing Configuration Loading...")
        
        # Test basic configuration loading
        self.assertEqual(self.config.environment.value, "development")
        self.assertEqual(self.config.rate_limit.max_requests, 5)
        self.assertEqual(self.config.circuit_breaker.failure_threshold, 3)
        self.assertEqual(self.config.retry.max_attempts, 2)
        
        # Test configuration summary
        summary = ConfigLoader.get_configuration_summary(self.config)
        self.assertIn("environment", summary)
        self.assertIn("rate_limit", summary)
        self.assertIn("circuit_breaker", summary)
        
        print("✅ Configuration loading tests passed")
    
    def test_structured_logging(self):
        """Test structured logging functionality"""
        print("\n📝 Testing Structured Logging...")
        
        # Test basic logging
        self.logger.info("Test info message", operation="test_operation")
        self.logger.audit("Test audit message", operation="test_audit", item_name="test_item")
        self.logger.security("Test security message", operation="test_security")
        
        # Test correlation context
        with CorrelationContext("test-correlation-123"):
            self.logger.info("Message with correlation ID")
        
        # Test sensitive data scrubbing
        scrubber = SensitiveDataScrubber()
        
        test_data = {
            "username": "testuser",
            "password": "secret123",
            "api_key": "abc123",
            "normal_field": "safe_value"
        }
        
        scrubbed = scrubber.scrub_dict(test_data)
        self.assertEqual(scrubbed["password"], "[REDACTED]")
        self.assertEqual(scrubbed["api_key"], "[REDACTED]")
        self.assertEqual(scrubbed["normal_field"], "safe_value")
        
        print("✅ Structured logging tests passed")
    
    async def test_circuit_breaker(self):
        """Test circuit breaker functionality"""
        print("\n⚡ Testing Circuit Breaker...")
        
        config = CircuitBreakerConfig(
            failure_threshold=2,
            recovery_timeout=1,
            success_threshold=1,
            timeout=1.0
        )
        circuit_breaker = CircuitBreaker(config)
        
        # Test successful operation
        async def success_func():
            return "success"
        
        result = await circuit_breaker.call(success_func)
        self.assertEqual(result, "success")
        
        # Test failing operation that opens circuit
        async def failing_func():
            raise Exception("Test failure")
        
        # First failures should go through
        with self.assertRaises(Exception):
            await circuit_breaker.call(failing_func)
        
        with self.assertRaises(Exception):
            await circuit_breaker.call(failing_func)
        
        # Next call should be rejected by open circuit
        from resilience import CircuitBreakerOpenError
        with self.assertRaises(CircuitBreakerOpenError):
            await circuit_breaker.call(failing_func)
        
        # Get stats
        stats = circuit_breaker.get_stats()
        self.assertEqual(stats["state"], "open")
        self.assertEqual(stats["failed_requests"], 2)
        
        print("✅ Circuit breaker tests passed")
    
    async def test_retry_logic(self):
        """Test retry logic with exponential backoff"""
        print("\n🔄 Testing Retry Logic...")
        
        config = RetryConfig(
            max_attempts=3,
            base_delay=0.1,  # Fast for testing
            max_delay=1.0,
            exponential_base=2.0,
            jitter=False  # Disable for predictable testing
        )
        
        # Test successful retry
        attempt_count = 0
        
        async def flaky_func():
            nonlocal attempt_count
            attempt_count += 1
            if attempt_count < 3:
                raise ConnectionError("Connection failed")
            return "success"
        
        start_time = time.time()
        result = await retry_with_backoff(
            flaky_func,
            config,
            retryable_exceptions=(ConnectionError,)
        )
        duration = time.time() - start_time
        
        self.assertEqual(result, "success")
        self.assertEqual(attempt_count, 3)
        self.assertGreater(duration, 0.2)  # Should have some delay from retries
        
        print("✅ Retry logic tests passed")
    
    def test_metrics_collection(self):
        """Test metrics collection functionality"""
        print("\n📊 Testing Metrics Collection...")
        
        # Create different types of metrics
        counter = self.metrics_collector.create_counter("test_counter", "Test counter metric")
        gauge = self.metrics_collector.create_gauge("test_gauge", "Test gauge metric")
        histogram = self.metrics_collector.create_histogram("test_histogram", "Test histogram metric")
        
        # Test counter
        self.metrics_collector.increment_counter("test_counter", 5)
        self.metrics_collector.increment_counter("test_counter", 3)
        self.assertEqual(counter.get_current_value(), 8)
        
        # Test gauge
        self.metrics_collector.set_gauge("test_gauge", 42.5)
        self.assertEqual(gauge.get_current_value(), 42.5)
        
        # Test histogram
        self.metrics_collector.record_histogram("test_histogram", 100)
        self.metrics_collector.record_histogram("test_histogram", 200)
        self.assertEqual(histogram.get_current_value(), 200)
        
        # Test metrics summary
        summary = self.metrics_collector.get_metrics_summary()
        self.assertIn("metrics", summary)
        self.assertIn("test_counter", summary["metrics"])
        
        print("✅ Metrics collection tests passed")
    
    async def test_health_checks(self):
        """Test health check functionality"""
        print("\n🏥 Testing Health Checks...")
        
        health_checker = HealthChecker(self.metrics_collector)
        
        # Register test health checks
        async def healthy_check():
            return {"status": "healthy", "message": "All good"}
        
        async def unhealthy_check():
            return {"status": "unhealthy", "message": "Something wrong"}
        
        health_checker.register_check("healthy_test", healthy_check)
        health_checker.register_check("unhealthy_test", unhealthy_check)
        
        # Run health checks
        health = await health_checker.run_all_checks()
        
        self.assertEqual(health.overall_status.value, "unhealthy")  # One unhealthy check
        self.assertEqual(len(health.checks), 2)
        
        # Find specific check results
        healthy_result = next(c for c in health.checks if c.name == "healthy_test")
        unhealthy_result = next(c for c in health.checks if c.name == "unhealthy_test")
        
        self.assertEqual(healthy_result.status.value, "healthy")
        self.assertEqual(unhealthy_result.status.value, "unhealthy")
        
        print("✅ Health check tests passed")
    
    def test_rate_limiting(self):
        """Test rate limiting functionality"""
        print("\n⏱️ Testing Rate Limiting...")
        
        from server import RateLimiter
        
        rate_limiter = RateLimiter(3, 1, self.metrics_collector)  # 3 requests per second
        
        # Test within rate limit
        allowed, remaining = rate_limiter.is_allowed("test_client")
        self.assertTrue(allowed)
        self.assertEqual(remaining, 2)
        
        allowed, remaining = rate_limiter.is_allowed("test_client")
        self.assertTrue(allowed)
        self.assertEqual(remaining, 1)
        
        allowed, remaining = rate_limiter.is_allowed("test_client")
        self.assertTrue(allowed)
        self.assertEqual(remaining, 0)
        
        # Test rate limit exceeded
        allowed, remaining = rate_limiter.is_allowed("test_client")
        self.assertFalse(allowed)
        self.assertEqual(remaining, 0)
        
        print("✅ Rate limiting tests passed")
    
    async def test_error_scenarios(self):
        """Test various error handling scenarios"""
        print("\n❌ Testing Error Handling Scenarios...")
        
        # Test timeout error
        from resilience import timeout_context, TimeoutError
        
        async def slow_operation():
            await asyncio.sleep(2)
            return "result"
        
        with self.assertRaises(TimeoutError):
            async with timeout_context(0.1):
                await slow_operation()
        
        # Test non-retryable error
        from resilience import NonRetryableError
        
        async def non_retryable_func():
            raise NonRetryableError("This should not be retried")
        
        config = RetryConfig(max_attempts=3, base_delay=0.01)
        
        with self.assertRaises(NonRetryableError):
            await retry_with_backoff(
                non_retryable_func,
                config,
                retryable_exceptions=(ConnectionError,),
                non_retryable_exceptions=(NonRetryableError,)
            )
        
        print("✅ Error handling tests passed")


async def run_all_tests():
    """Run all P1 feature tests"""
    print("🚀 Starting P1 Features Test Suite")
    print("=" * 50)
    
    test_suite = TestP1Features()
    test_suite.setUp()
    
    try:
        # Run synchronous tests
        test_suite.test_configuration_loading()
        test_suite.test_structured_logging()
        test_suite.test_metrics_collection()
        test_suite.test_rate_limiting()
        
        # Run asynchronous tests
        await test_suite.test_circuit_breaker()
        await test_suite.test_retry_logic()
        await test_suite.test_health_checks()
        await test_suite.test_error_scenarios()
        
        print("\n" + "=" * 50)
        print("🎉 All P1 Features Tests Passed!")
        print("✅ Error Handling & Resilience")
        print("✅ Structured Logging & Monitoring")
        print("✅ Configuration Management")
        print("✅ Health Checks & Metrics")
        print("✅ Rate Limiting & Security")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        raise


def demonstrate_features():
    """Demonstrate P1 features with examples"""
    print("\n" + "=" * 50)
    print("📋 P1 Features Demonstration")
    print("=" * 50)
    
    print("\n1. 🔧 Configuration Management:")
    print("   - Environment-based configuration loading")
    print("   - Validation and warnings")
    print("   - Production-ready defaults")
    
    print("\n2. 📝 Structured Logging:")
    print("   - JSON-formatted logs with correlation IDs")
    print("   - Audit logging for security events")
    print("   - Automatic sensitive data scrubbing")
    
    print("\n3. ⚡ Resilience Patterns:")
    print("   - Circuit breaker for 1Password API calls")
    print("   - Retry logic with exponential backoff")
    print("   - Configurable timeouts and thresholds")
    
    print("\n4. 📊 Monitoring & Health Checks:")
    print("   - Comprehensive metrics collection")
    print("   - Health check endpoints")
    print("   - Operational dashboard data")
    
    print("\n5. 🛡️ Enhanced Security:")
    print("   - Rate limiting with metrics")
    print("   - Input validation and sanitization")
    print("   - Security event monitoring")
    
    print("\n6. 🔍 Error Handling:")
    print("   - Comprehensive error classification")
    print("   - Graceful degradation strategies")
    print("   - Detailed error reporting and tracking")


if __name__ == "__main__":
    try:
        asyncio.run(run_all_tests())
        demonstrate_features()
    except Exception as e:
        print(f"Test execution failed: {e}")
        exit(1)