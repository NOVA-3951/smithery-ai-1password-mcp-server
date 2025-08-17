#!/usr/bin/env python3
"""
Structured logging implementation for the 1Password MCP Server
Includes JSON formatting, correlation IDs, audit logging, and log scrubbing
"""

import json
import logging
import sys
import time
import uuid
from typing import Any, Dict, Optional, Set
from contextvars import ContextVar
from datetime import datetime
from dataclasses import dataclass, asdict
from enum import Enum


# Context variable for correlation ID
correlation_id: ContextVar[Optional[str]] = ContextVar('correlation_id', default=None)


class LogLevel(Enum):
    """Log levels"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class EventType(Enum):
    """Event types for structured logging"""
    SECURITY = "security"
    AUDIT = "audit"
    PERFORMANCE = "performance"
    ERROR = "error"
    ACCESS = "access"
    SYSTEM = "system"


@dataclass
class LogEvent:
    """Structured log event"""
    timestamp: str
    level: str
    event_type: str
    correlation_id: Optional[str]
    message: str
    component: str
    operation: Optional[str] = None
    duration_ms: Optional[float] = None
    user_id: Optional[str] = None
    item_name: Optional[str] = None
    vault: Optional[str] = None
    error_code: Optional[str] = None
    request_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class SensitiveDataScrubber:
    """Scrub sensitive data from logs"""
    
    def __init__(self):
        # Patterns that indicate sensitive data
        self.sensitive_patterns = {
            'password', 'passwd', 'pwd', 'secret', 'token', 'key', 'credential',
            'auth', 'session', 'cookie', 'bearer', 'jwt', 'api_key', 'private',
            'confidential', 'sensitive'
        }
        
        # Fields that should always be scrubbed
        self.always_scrub = {
            'password', 'secret', 'token', 'key', 'private_key', 'api_key',
            'access_token', 'refresh_token', 'session_token', 'auth_token'
        }
    
    def scrub_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Scrub sensitive data from dictionary"""
        if not isinstance(data, dict):
            return data
        
        scrubbed = {}
        for key, value in data.items():
            if self._is_sensitive_key(key):
                scrubbed[key] = "[REDACTED]"
            elif isinstance(value, dict):
                scrubbed[key] = self.scrub_dict(value)
            elif isinstance(value, list):
                scrubbed[key] = [
                    self.scrub_dict(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                scrubbed[key] = value
        
        return scrubbed
    
    def scrub_string(self, text: str) -> str:
        """Scrub sensitive data from string"""
        # Look for patterns like key=value, "key":"value", etc.
        import re
        
        # Pattern for key-value pairs with potentially sensitive keys
        pattern = r'(["\']?)(\w*(?:' + '|'.join(self.sensitive_patterns) + r')\w*)(["\']?)\s*[:=]\s*(["\']?)([^,\s}\]]+)(["\']?)'
        
        def replace_sensitive(match):
            quote1, key, quote2, quote3, value, quote4 = match.groups()
            return f'{quote1}{key}{quote2}{quote3}[REDACTED]{quote4}'
        
        return re.sub(pattern, replace_sensitive, text, flags=re.IGNORECASE)
    
    def _is_sensitive_key(self, key: str) -> bool:
        """Check if key indicates sensitive data"""
        key_lower = key.lower()
        
        # Always scrub certain fields
        if key_lower in self.always_scrub:
            return True
        
        # Check if key contains sensitive patterns
        return any(pattern in key_lower for pattern in self.sensitive_patterns)


class StructuredLogger:
    """Structured logger with JSON formatting and correlation tracking"""
    
    def __init__(self, component: str, level: LogLevel = LogLevel.INFO):
        self.component = component
        self.scrubber = SensitiveDataScrubber()
        self.logger = logging.getLogger(component)
        self.logger.setLevel(getattr(logging, level.value))
        
        # Remove default handlers
        self.logger.handlers.clear()
        
        # Add structured handler
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(StructuredFormatter(self.scrubber))
        self.logger.addHandler(handler)
    
    def _create_event(
        self,
        level: LogLevel,
        event_type: EventType,
        message: str,
        operation: Optional[str] = None,
        duration_ms: Optional[float] = None,
        user_id: Optional[str] = None,
        item_name: Optional[str] = None,
        vault: Optional[str] = None,
        error_code: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> LogEvent:
        """Create a structured log event"""
        return LogEvent(
            timestamp=datetime.utcnow().isoformat() + "Z",
            level=level.value,
            event_type=event_type.value,
            correlation_id=correlation_id.get(),
            message=message,
            component=self.component,
            operation=operation,
            duration_ms=duration_ms,
            user_id=user_id,
            item_name=item_name,
            vault=vault,
            error_code=error_code,
            request_id=request_id,
            metadata=self.scrubber.scrub_dict(metadata) if metadata else None
        )
    
    def debug(self, message: str, **kwargs):
        """Log debug message"""
        event = self._create_event(LogLevel.DEBUG, EventType.SYSTEM, message, **kwargs)
        self.logger.debug(event)
    
    def info(self, message: str, **kwargs):
        """Log info message"""
        event = self._create_event(LogLevel.INFO, EventType.SYSTEM, message, **kwargs)
        self.logger.info(event)
    
    def warning(self, message: str, **kwargs):
        """Log warning message"""
        event = self._create_event(LogLevel.WARNING, EventType.SYSTEM, message, **kwargs)
        self.logger.warning(event)
    
    def error(self, message: str, **kwargs):
        """Log error message"""
        event = self._create_event(LogLevel.ERROR, EventType.ERROR, message, **kwargs)
        self.logger.error(event)
    
    def critical(self, message: str, **kwargs):
        """Log critical message"""
        event = self._create_event(LogLevel.CRITICAL, EventType.ERROR, message, **kwargs)
        self.logger.critical(event)
    
    def audit(self, message: str, **kwargs):
        """Log audit event"""
        event = self._create_event(LogLevel.INFO, EventType.AUDIT, message, **kwargs)
        self.logger.info(event)
    
    def security(self, message: str, **kwargs):
        """Log security event"""
        event = self._create_event(LogLevel.WARNING, EventType.SECURITY, message, **kwargs)
        self.logger.warning(event)
    
    def performance(self, message: str, duration_ms: float, **kwargs):
        """Log performance event"""
        event = self._create_event(
            LogLevel.INFO, 
            EventType.PERFORMANCE, 
            message, 
            duration_ms=duration_ms,
            **kwargs
        )
        self.logger.info(event)
    
    def access(self, message: str, **kwargs):
        """Log access event"""
        event = self._create_event(LogLevel.INFO, EventType.ACCESS, message, **kwargs)
        self.logger.info(event)


class StructuredFormatter(logging.Formatter):
    """JSON formatter for structured logs"""
    
    def __init__(self, scrubber: SensitiveDataScrubber):
        super().__init__()
        self.scrubber = scrubber
    
    def format(self, record) -> str:
        """Format log record as JSON"""
        if isinstance(record.msg, LogEvent):
            # Already structured
            log_dict = asdict(record.msg)
        else:
            # Convert regular log to structured format
            log_dict = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "level": record.levelname,
                "event_type": "system",
                "correlation_id": correlation_id.get(),
                "message": self.scrubber.scrub_string(str(record.msg)),
                "component": record.name,
                "operation": None,
                "duration_ms": None,
                "user_id": None,
                "item_name": None,
                "vault": None,
                "error_code": None,
                "request_id": None,
                "metadata": None
            }
        
        # Remove None values
        log_dict = {k: v for k, v in log_dict.items() if v is not None}
        
        # Scrub the entire dictionary
        log_dict = self.scrubber.scrub_dict(log_dict)
        
        return json.dumps(log_dict, ensure_ascii=False)


class CorrelationContext:
    """Context manager for correlation ID"""
    
    def __init__(self, correlation_id_value: Optional[str] = None):
        self.correlation_id_value = correlation_id_value or str(uuid.uuid4())
        self.token = None
    
    def __enter__(self):
        self.token = correlation_id.set(self.correlation_id_value)
        return self.correlation_id_value
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.token:
            correlation_id.reset(self.token)


class PerformanceTimer:
    """Context manager for timing operations"""
    
    def __init__(self, logger: StructuredLogger, operation: str, **kwargs):
        self.logger = logger
        self.operation = operation
        self.kwargs = kwargs
        self.start_time = None
        self.duration_ms = None
    
    def __enter__(self):
        self.start_time = time.perf_counter()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.start_time:
            self.duration_ms = (time.perf_counter() - self.start_time) * 1000
            
            if exc_type:
                self.logger.error(
                    f"Operation failed: {self.operation}",
                    operation=self.operation,
                    duration_ms=self.duration_ms,
                    error_code=exc_type.__name__,
                    **self.kwargs
                )
            else:
                self.logger.performance(
                    f"Operation completed: {self.operation}",
                    duration_ms=self.duration_ms,
                    operation=self.operation,
                    **self.kwargs
                )


def get_logger(component: str) -> StructuredLogger:
    """Get a structured logger for the component"""
    return StructuredLogger(component)


def with_correlation_id(correlation_id_value: Optional[str] = None):
    """Decorator to add correlation ID to function"""
    def decorator(func):
        async def async_wrapper(*args, **kwargs):
            with CorrelationContext(correlation_id_value):
                return await func(*args, **kwargs)
        
        def sync_wrapper(*args, **kwargs):
            with CorrelationContext(correlation_id_value):
                return func(*args, **kwargs)
        
        if hasattr(func, '__code__') and 'await' in func.__code__.co_names:
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator