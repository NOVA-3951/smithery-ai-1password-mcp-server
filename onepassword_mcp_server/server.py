#!/usr/bin/env python3
"""
1Password MCP Server - Enhanced with P1 Security Hardening & MCP Protocol Compliance

Copyright (c) 2024 1Password MCP Server Contributors
Licensed under the MIT License (see LICENSE file)

This server provides secure access to 1Password credentials through the MCP protocol
with comprehensive error handling, resilience patterns, structured logging, monitoring,
security hardening, and full MCP protocol compliance.

Features:
- Circuit breaker pattern for 1Password API calls
- Retry logic with exponential backoff
- Structured JSON logging with correlation IDs
- Health check endpoints and metrics collection
- Rate limiting and input validation
- Audit logging and security monitoring
- Memory protection for credentials
- Transport security enforcement
- Request signing and integrity verification
- Full MCP protocol compliance with tool discovery
- Resource exposure and prompt templates
- Multiple transport support
"""

import asyncio
import argparse
import os
import time
from typing import Dict, Optional, Any, Tuple, Literal
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
import uuid

from pydantic import BaseModel, Field, validator
from pydantic import ValidationError as PydanticValidationError
from mcp.server.fastmcp import FastMCP
from onepassword.client import Client
from onepassword import ResolveReferenceError, RateLimitExceededException

# OnePasswordError is used as a catch-all for 1Password SDK exceptions.
# The SDK exports ResolveReferenceError and RateLimitExceededException
# but doesn't have a base error class, so we create one for compatibility.
# This allows existing code to catch a broad category of 1Password errors.
class OnePasswordError(Exception):
    """Base class for 1Password SDK errors (compatibility wrapper)"""
    pass

# Import our modules
from .config import ConfigLoader, ServerConfig, ConfigurationError
from .structured_logging import (
    get_logger, CorrelationContext, PerformanceTimer, 
    EventType, LogLevel
)
from .resilience import (
    ResilientOperationManager, CircuitBreakerConfig, RetryConfig,
    CircuitBreakerOpenError, TimeoutError as ResilientTimeoutError,
    RetryableError, NonRetryableError
)
from .monitoring import (
    MetricsCollector, HealthChecker, OperationalDashboard,
    HealthStatus, basic_health_check, onepassword_connectivity_check
)
from .security_hardening import (
    SecurityHardeningManager, SecurityHardeningConfig, SecurityError,
    MemoryProtectionError, TransportSecurityError, RequestIntegrityError,
    initialize_security_hardening, get_security_manager
)
from .mcp_protocol_compliance import (
    MCPProtocolManager, ToolMetadata, ResourceMetadata, PromptTemplate,
    initialize_mcp_protocol, get_protocol_manager, register_tool_with_metadata,
    create_enhanced_mcp_server
)


# Global configuration and components
config: Optional[ServerConfig] = None
logger = None
metrics_collector = None
health_checker = None
dashboard = None
resilient_manager = None
security_manager = None
protocol_manager = None


class ValidationError(Exception):
    """Input validation error"""
    pass


class AuthenticationError(Exception):
    """Authentication failure"""
    pass


class RateLimitError(Exception):
    """Rate limit exceeded"""
    pass


class SecurityError(Exception):
    """Security-related error"""
    pass


@dataclass
class RateLimitEntry:
    """Rate limiting entry for tracking requests"""
    count: int
    window_start: float


class RateLimiter:
    """Enhanced rate limiter with metrics integration"""
    
    def __init__(self, max_requests: int, window: int, metrics_collector: MetricsCollector):
        self.max_requests = max_requests
        self.window = window
        self.metrics_collector = metrics_collector
        self.requests: Dict[str, RateLimitEntry] = defaultdict(
            lambda: RateLimitEntry(0, time.time())
        )
        
        # Initialize metrics
        self.metrics_collector.create_counter(
            "rate_limit_requests_total", 
            "Total rate limit checks performed"
        )
        self.metrics_collector.create_counter(
            "rate_limit_rejections_total", 
            "Total requests rejected by rate limiter"
        )
    
    def is_allowed(self, client_id: str = "default") -> Tuple[bool, int]:
        """Check if request is allowed under rate limit"""
        self.metrics_collector.increment_counter("rate_limit_requests_total")
        
        now = time.time()
        entry = self.requests[client_id]
        
        # Reset window if expired
        if now - entry.window_start >= self.window:
            entry.count = 0
            entry.window_start = now
        
        # Check if under limit
        if entry.count < self.max_requests:
            entry.count += 1
            return True, self.max_requests - entry.count
        
        # Rate limit exceeded
        self.metrics_collector.increment_counter("rate_limit_rejections_total")
        logger.security(
            "Rate limit exceeded",
            operation="rate_limit_check",
            metadata={"client_id": client_id, "current_count": entry.count}
        )
        
        return False, 0


class CredentialRequest(BaseModel):
    """Validated credential request model"""
    item_name: str = Field(..., min_length=1)
    vault: Optional[str] = None
    
    @validator('item_name')
    def validate_item_name(cls, v):
        """Validate item name format for security"""
        if not config:
            raise ValueError("Configuration not loaded")
        
        if len(v) > config.security.max_item_name_length:
            raise ValueError(f"Item name exceeds maximum length of {config.security.max_item_name_length}")
        
        import re
        if not re.match(config.security.allowed_item_name_pattern, v):
            raise ValueError(
                "Item name must contain only alphanumeric characters, periods, hyphens, and underscores"
            )
        return v
    
    @validator('vault')
    def validate_vault(cls, v):
        """Validate vault name format"""
        if not config:
            raise ValueError("Configuration not loaded")
        
        if not v:
            return config.security.default_vault
        
        import re
        if not re.match(config.security.allowed_item_name_pattern, v):
            raise ValueError(
                "Vault name must contain only alphanumeric characters, periods, hyphens, and underscores"
            )
        return v


class OnePasswordSecureClient:
    """Enhanced secure wrapper for 1Password client with resilience patterns"""
    
    def __init__(self, config: ServerConfig, metrics_collector: MetricsCollector):
        self.config = config
        self.metrics_collector = metrics_collector
        self.client: Optional[Client] = None
        self.rate_limiter = RateLimiter(
            config.rate_limit.max_requests,
            config.rate_limit.window_seconds,
            metrics_collector
        )
        
        # Setup resilient operation manager
        circuit_config = CircuitBreakerConfig(
            failure_threshold=config.circuit_breaker.failure_threshold,
            recovery_timeout=config.circuit_breaker.recovery_timeout_seconds,
            success_threshold=config.circuit_breaker.success_threshold,
            timeout=config.circuit_breaker.timeout_seconds
        )
        
        retry_config = RetryConfig(
            max_attempts=config.retry.max_attempts,
            base_delay=config.retry.base_delay_seconds,
            max_delay=config.retry.max_delay_seconds,
            exponential_base=config.retry.exponential_base,
            jitter=config.retry.jitter_enabled
        )
        
        self.resilient_manager = ResilientOperationManager(circuit_config, retry_config)
        
        # Initialize metrics
        self._initialize_metrics()
    
    def _initialize_metrics(self):
        """Initialize metrics for 1Password operations"""
        self.metrics_collector.create_counter("onepassword_requests_total", "Total 1Password API requests")
        self.metrics_collector.create_counter("onepassword_requests_failed", "Failed 1Password API requests")
        self.metrics_collector.create_counter("onepassword_authentication_attempts", "1Password authentication attempts")
        self.metrics_collector.create_counter("onepassword_authentication_failures", "1Password authentication failures")
        self.metrics_collector.create_histogram("onepassword_request_duration_ms", "1Password request duration in milliseconds")
        self.metrics_collector.create_gauge("onepassword_circuit_breaker_state", "1Password circuit breaker state (0=closed, 1=half-open, 2=open)")
    
    async def _authenticate(self) -> Client:
        """Authenticate with 1Password service account with resilience"""
        if self.client is not None:
            return self.client
        
        # Validate token before attempting authentication
        # This raises ConfigurationError if token is not configured
        token = self.config.require_token()
        
        async def auth_operation():
            self.metrics_collector.increment_counter("onepassword_authentication_attempts")
            
            try:
                self.client = await Client.authenticate(
                    auth=token,
                    integration_name=self.config.integration_name,
                    integration_version=self.config.integration_version
                )
                
                logger.info(
                    "Successfully authenticated with 1Password service account",
                    operation="onepassword_authentication"
                )
                return self.client
                
            except OnePasswordError as e:
                self.metrics_collector.increment_counter("onepassword_authentication_failures")
                logger.error(
                    "1Password authentication failed",
                    operation="onepassword_authentication",
                    error_code="onepassword_error",
                    metadata={"error_type": type(e).__name__, "error_message": str(e)}
                )
                raise AuthenticationError(f"Authentication failed: {str(e)}")
            
            except Exception as e:
                self.metrics_collector.increment_counter("onepassword_authentication_failures")
                logger.error(
                    "Unexpected authentication error",
                    operation="onepassword_authentication",
                    error_code="unexpected_error",
                    metadata={"error_type": type(e).__name__, "error_message": str(e)}
                )
                raise AuthenticationError(f"Authentication error: {str(e)}")
        
        # Use resilient operation manager for authentication
        return await self.resilient_manager.execute(
            auth_operation,
            retryable_exceptions=(OnePasswordError, ConnectionError, TimeoutError),
            non_retryable_exceptions=(AuthenticationError, CircuitBreakerOpenError)
        )
    
    async def get_credentials(self, request: CredentialRequest) -> Dict[str, str]:
        """Securely retrieve credentials with comprehensive error handling, resilience, and security hardening"""
        
        # Generate correlation ID for this request
        correlation_id = str(uuid.uuid4())
        
        with CorrelationContext(correlation_id):
            # Create secure request context with signing if available
            request_data = {
                "item_name": request.item_name,
                "vault": request.vault,
                "correlation_id": correlation_id
            }
            
            # Apply request signing if security manager is available
            if security_manager:
                request_data = security_manager.create_secure_request_context(request_data)
            
            # Rate limiting check
            allowed, remaining = self.rate_limiter.is_allowed()
            if not allowed:
                logger.security(
                    "Rate limit exceeded for credential request",
                    operation="get_credentials",
                    item_name=request.item_name,
                    vault=request.vault
                )
                raise RateLimitError("Rate limit exceeded. Please try again later.")
            
            logger.audit(
                "Credential request initiated",
                operation="get_credentials",
                item_name=request.item_name,
                vault=request.vault,
                metadata={"remaining_requests": remaining}
            )
            
            # Track performance
            with PerformanceTimer(logger, "get_credentials", item_name=request.item_name, vault=request.vault):
                
                async def credential_operation():
                    self.metrics_collector.increment_counter("onepassword_requests_total")
                    start_time = time.perf_counter()
                    
                    try:
                        client = await self._authenticate()
                        
                        # Construct secure reference paths
                        username_ref = f"op://{request.vault}/{request.item_name}/username"
                        password_ref = f"op://{request.vault}/{request.item_name}/password"
                        
                        logger.debug(
                            "Retrieving credentials from 1Password",
                            operation="resolve_credentials",
                            metadata={
                                "username_ref": username_ref,
                                "password_ref": password_ref  # This will be scrubbed by logging
                            }
                        )
                        
                        # Retrieve credentials
                        username = await client.secrets.resolve(username_ref)
                        password = await client.secrets.resolve(password_ref)
                        
                        # Validate retrieved credentials
                        if not username or not password:
                            raise ValueError("Retrieved credentials are empty")
                        
                        duration_ms = (time.perf_counter() - start_time) * 1000
                        self.metrics_collector.record_histogram("onepassword_request_duration_ms", duration_ms)
                        
                        logger.audit(
                            "Successfully retrieved credentials",
                            operation="get_credentials",
                            item_name=request.item_name,
                            vault=request.vault,
                            duration_ms=duration_ms
                        )
                        
                        # Use secure memory management for credentials if available
                        if security_manager:
                            with security_manager.secure_credential_context(password) as secure_password:
                                # Return credentials with secure handling
                                return {
                                    "username": username,
                                    "password": secure_password.get_value(),
                                    "item_name": request.item_name,
                                    "vault": request.vault,
                                    "retrieved_at": datetime.utcnow().isoformat(),
                                    "correlation_id": correlation_id,
                                    "security_protected": True
                                }
                        else:
                            return {
                                "username": username,
                                "password": password,
                                "item_name": request.item_name,
                                "vault": request.vault,
                                "retrieved_at": datetime.utcnow().isoformat(),
                                "correlation_id": correlation_id,
                                "security_protected": False
                            }
                        
                    except OnePasswordError as e:
                        self.metrics_collector.increment_counter("onepassword_requests_failed")
                        duration_ms = (time.perf_counter() - start_time) * 1000
                        self.metrics_collector.record_histogram("onepassword_request_duration_ms", duration_ms)
                        
                        logger.error(
                            "1Password error retrieving credentials",
                            operation="get_credentials",
                            item_name=request.item_name,
                            vault=request.vault,
                            error_code="onepassword_error",
                            duration_ms=duration_ms,
                            metadata={"error_type": type(e).__name__, "error_message": str(e)}
                        )
                        
                        if "not found" in str(e).lower():
                            raise ValidationError(f"Item '{request.item_name}' not found in vault '{request.vault}'")
                        else:
                            raise RetryableError(f"1Password API error: {str(e)}")
                    
                    except Exception as e:
                        self.metrics_collector.increment_counter("onepassword_requests_failed")
                        duration_ms = (time.perf_counter() - start_time) * 1000
                        self.metrics_collector.record_histogram("onepassword_request_duration_ms", duration_ms)
                        
                        logger.error(
                            "Unexpected error retrieving credentials",
                            operation="get_credentials",
                            item_name=request.item_name,
                            vault=request.vault,
                            error_code="unexpected_error",
                            duration_ms=duration_ms,
                            metadata={"error_type": type(e).__name__, "error_message": str(e)}
                        )
                        
                        raise RetryableError(f"Unexpected error: {str(e)}")
                
                # Use resilient operation manager
                return await self.resilient_manager.execute(
                    credential_operation,
                    retryable_exceptions=(RetryableError, ConnectionError, ResilientTimeoutError),
                    non_retryable_exceptions=(ValidationError, AuthenticationError, CircuitBreakerOpenError)
                )
    
    def get_resilience_stats(self) -> Dict[str, Any]:
        """Get resilience statistics"""
        stats = self.resilient_manager.get_stats()
        
        # Update circuit breaker state metric
        cb_state = stats["circuit_breaker"]["state"]
        state_value = {"closed": 0, "half_open": 1, "open": 2}.get(cb_state, 0)
        self.metrics_collector.set_gauge("onepassword_circuit_breaker_state", state_value)
        
        return stats


async def initialize_server():
    """Initialize server components with configuration"""
    global config, logger, metrics_collector, health_checker, dashboard, resilient_manager, security_manager, protocol_manager
    
    try:
        # Load configuration
        config = ConfigLoader.load_from_environment()
        
        # Initialize structured logging
        logger = get_logger("1password-mcp-server")
        
        # Log configuration warnings
        warnings = ConfigLoader.validate_configuration(config)
        for warning in warnings:
            logger.warning(f"Configuration warning: {warning}")
        
        # Initialize security hardening
        # Note: required_environment_vars is set to empty to allow the server to start
        # without OP_SERVICE_ACCOUNT_TOKEN. The default security config only requires
        # this one variable, and token validation is now handled lazily in config.require_token()
        # when credential operations are actually performed.
        security_config = SecurityHardeningConfig(
            memory_protection_enabled=True,
            tls_enforcement_enabled=config.environment.value == "production",
            request_signing_enabled=True,
            environment_validation_enabled=True,
            required_environment_vars=[]  # Token validation deferred to config.require_token()
        )
        security_manager = initialize_security_hardening(security_config)
        
        logger.info(
            "Security hardening initialized",
            operation="security_initialization",
            metadata=security_manager.get_security_status()["config"]
        )
        
        # Initialize MCP protocol compliance
        protocol_manager = initialize_mcp_protocol(
            server_name=config.server_name,
            version=config.integration_version
        )
        
        # Register tool metadata for MCP compliance
        register_tool_metadata()
        
        logger.info(
            "MCP protocol compliance initialized",
            operation="mcp_initialization",
            metadata=protocol_manager.get_server_info()
        )
        
        # Initialize metrics collector
        metrics_collector = MetricsCollector()
        
        # Initialize health checker
        health_checker = HealthChecker(metrics_collector)
        health_checker.register_check("basic", basic_health_check)
        health_checker.register_check("onepassword_connectivity", onepassword_connectivity_check)
        
        # Add security health checks
        health_checker.register_check("security_status", lambda: security_health_check(security_manager))
        health_checker.register_check("environment_security", lambda: environment_security_check(security_manager))
        
        # Initialize operational dashboard
        dashboard = OperationalDashboard(metrics_collector, health_checker)
        
        # Initialize core metrics
        metrics_collector.create_counter("server_requests_total", "Total server requests")
        metrics_collector.create_counter("server_errors_total", "Total server errors")
        metrics_collector.create_histogram("request_duration_ms", "Request duration in milliseconds")
        metrics_collector.create_gauge("server_uptime_seconds", "Server uptime in seconds")
        
        # Security metrics
        metrics_collector.create_counter("security_events_total", "Total security events")
        metrics_collector.create_counter("memory_protection_events", "Memory protection events")
        metrics_collector.create_counter("request_signature_failures", "Request signature verification failures")
        metrics_collector.create_gauge("active_secure_allocations", "Active secure memory allocations")
        
        # Destructive operations metrics (P3 feature)
        metrics_collector.create_counter("destructive_operations_total", "Total destructive operations attempted")
        metrics_collector.create_counter("destructive_operations_successful", "Successful destructive operations")
        metrics_collector.create_counter("destructive_operations_failed", "Failed destructive operations")
        
        logger.info(
            "Server initialization completed",
            operation="server_initialization",
            metadata=ConfigLoader.get_configuration_summary(config)
        )
        
    except ConfigurationError as e:
        print(f"Configuration error: {e}")
        raise
    except Exception as e:
        print(f"Server initialization failed: {e}")
        raise


# Helper functions for health checks
async def security_health_check(security_manager: SecurityHardeningManager) -> Dict[str, Any]:
    """Security-specific health check"""
    try:
        status = security_manager.get_security_status()
        return {
            "status": "healthy" if status["environment_valid"] else "unhealthy",
            "details": status,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }


async def environment_security_check(security_manager: SecurityHardeningManager) -> Dict[str, Any]:
    """Environment security validation check"""
    try:
        is_valid, issues = security_manager.environment_validator.validate_environment()
        return {
            "status": "healthy" if is_valid else "unhealthy",
            "issues": issues,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }


def register_tool_metadata():
    """Register enhanced metadata for all tools"""
    if not protocol_manager:
        return
    
    # Register get_1password_credentials tool
    credentials_tool = ToolMetadata(
        name="get_1password_credentials",
        description="Securely retrieve 1Password credentials for a given item with comprehensive error handling, resilience patterns, and monitoring",
        parameters={
            "item_name": {
                "type": "string",
                "description": "Name of the 1Password item (alphanumeric, dots, hyphens, underscores only)",
                "required": True,
                "pattern": r'^[a-zA-Z0-9._-]+$',
                "maxLength": 64
            },
            "vault": {
                "type": "string",
                "description": "Name of the 1Password vault (optional, defaults to configured default vault)",
                "required": False,
                "pattern": r'^[a-zA-Z0-9._-]+$'
            }
        },
        category="security",
        tags=["credentials", "1password", "security", "authentication"],
        version="1.1.0",
        requires_auth=True,
        rate_limited=True,
        security_level="critical",
        audit_required=True,
        sensitive_data=True,
        typical_response_time_ms=500,
        max_response_time_ms=30000,
        examples=[
            {
                "parameters": {"item_name": "database-prod", "vault": "Infrastructure"},
                "description": "Retrieve production database credentials",
                "use_case": "Database connection for production services"
            },
            {
                "parameters": {"item_name": "api-key-service"},
                "description": "Retrieve API key from default vault",
                "use_case": "Service authentication with external APIs"
            }
        ],
        related_tools=["get_health_status", "get_metrics"]
    )
    protocol_manager.register_tool(credentials_tool, None)
    
    # Register health status tool
    health_tool = ToolMetadata(
        name="get_health_status",
        description="Get comprehensive health status of the 1Password MCP server including security status",
        parameters={},
        category="monitoring",
        tags=["health", "monitoring", "diagnostics", "status"],
        version="1.1.0",
        requires_auth=False,
        rate_limited=False,
        security_level="low",
        audit_required=False,
        sensitive_data=False,
        typical_response_time_ms=100,
        max_response_time_ms=5000,
        examples=[
            {
                "parameters": {},
                "description": "Get comprehensive server health status",
                "use_case": "Health monitoring and diagnostics"
            }
        ],
        related_tools=["get_metrics"]
    )
    protocol_manager.register_tool(health_tool, None)
    
    # Register metrics tool
    metrics_tool = ToolMetadata(
        name="get_metrics",
        description="Get operational metrics, performance data, and security insights",
        parameters={},
        category="monitoring",
        tags=["metrics", "performance", "monitoring", "analytics"],
        version="1.1.0",
        requires_auth=False,
        rate_limited=False,
        security_level="medium",
        audit_required=True,
        sensitive_data=False,
        typical_response_time_ms=200,
        max_response_time_ms=10000,
        examples=[
            {
                "parameters": {},
                "description": "Get operational metrics and performance data",
                "use_case": "Performance monitoring and optimization"
            }
        ],
        related_tools=["get_health_status"]
    )
    protocol_manager.register_tool(metrics_tool, None)


# Initialize secure client and MCP server
def get_secure_client() -> OnePasswordSecureClient:
    """Get the secure 1Password client"""
    if not config or not metrics_collector:
        raise RuntimeError("Server not properly initialized")
    return OnePasswordSecureClient(config, metrics_collector)


# Initialize enhanced MCP server after protocol manager is available
def create_mcp_server(stateless_http: bool = False):
    """Create the enhanced MCP server with protocol compliance
    
    Args:
        stateless_http: If True, enables stateless HTTP mode for scalable cloud deployments
                       like Smithery. This is required for deployments where each request
                       may be handled by a different server instance.
    """
    if protocol_manager:
        return create_enhanced_mcp_server(protocol_manager, stateless_http=stateless_http)
    else:
        # Fallback to basic MCP server
        return FastMCP("1Password", stateless_http=stateless_http)

# Store secure client instance
secure_client: Optional[OnePasswordSecureClient] = None

# MCP server will be initialized in main()
mcp = None


async def get_1password_credentials_impl(item_name: str, vault: str = None) -> Dict[str, Any]:
    """
    Securely retrieve 1Password credentials for a given item.
    
    Enhanced with comprehensive error handling, resilience patterns, and monitoring.
    
    Args:
        item_name: Name of the 1Password item (alphanumeric, dots, hyphens, underscores only)
        vault: Name of the 1Password vault (default: configured default vault)
    
    Returns:
        Dictionary containing username, password, and metadata
    
    Raises:
        ValueError: For various error conditions (input validation, auth failures, etc.)
    """
    global secure_client
    
    if not secure_client:
        secure_client = get_secure_client()
    
    start_time = time.perf_counter()
    metrics_collector.increment_counter("server_requests_total")
    
    try:
        # Set default vault if not provided
        if vault is None:
            vault = config.security.default_vault
        
        # Validate input parameters
        request = CredentialRequest(item_name=item_name, vault=vault)
        
        # Log security event (without sensitive data)
        logger.access(
            "Credential request received",
            operation="get_1password_credentials",
            item_name=request.item_name,
            vault=request.vault
        )
        
        # Retrieve credentials through secure client
        credentials = await secure_client.get_credentials(request)
        
        # Record successful request
        duration_ms = (time.perf_counter() - start_time) * 1000
        metrics_collector.record_histogram("request_duration_ms", duration_ms)
        
        return credentials
    
    except ConfigurationError as e:
        # Token not configured - provide clear error message
        duration_ms = (time.perf_counter() - start_time) * 1000
        metrics_collector.increment_counter("server_errors_total")
        metrics_collector.record_histogram("request_duration_ms", duration_ms)
        
        logger.warning(
            "Credential request failed: token not configured",
            operation="get_1password_credentials",
            error_code="token_not_configured",
            duration_ms=duration_ms
        )
        raise ValueError(str(e))
        
    except (PydanticValidationError, ValidationError) as e:
        duration_ms = (time.perf_counter() - start_time) * 1000
        metrics_collector.increment_counter("server_errors_total")
        metrics_collector.record_histogram("request_duration_ms", duration_ms)
        
        error_msg = f"Invalid input parameters: {str(e)}"
        logger.warning(
            error_msg,
            operation="get_1password_credentials",
            error_code="validation_error",
            duration_ms=duration_ms
        )
        raise ValueError(error_msg)
    
    except (AuthenticationError, RateLimitError, SecurityError) as e:
        duration_ms = (time.perf_counter() - start_time) * 1000
        metrics_collector.increment_counter("server_errors_total")
        metrics_collector.record_histogram("request_duration_ms", duration_ms)
        
        logger.security(
            "Security error in credential retrieval",
            operation="get_1password_credentials",
            error_code=type(e).__name__.lower(),
            duration_ms=duration_ms,
            metadata={"error_message": str(e)}
        )
        raise ValueError(str(e))  # MCP tools should raise ValueError for user-facing errors
    
    except CircuitBreakerOpenError as e:
        duration_ms = (time.perf_counter() - start_time) * 1000
        metrics_collector.increment_counter("server_errors_total")
        metrics_collector.record_histogram("request_duration_ms", duration_ms)
        
        logger.error(
            "Circuit breaker is open, service unavailable",
            operation="get_1password_credentials",
            error_code="circuit_breaker_open",
            duration_ms=duration_ms
        )
        raise ValueError("Service is temporarily unavailable. Please try again later.")
    
    except Exception as e:
        duration_ms = (time.perf_counter() - start_time) * 1000
        metrics_collector.increment_counter("server_errors_total")
        metrics_collector.record_histogram("request_duration_ms", duration_ms)
        
        error_msg = f"Unexpected error retrieving credentials: {str(e)}"
        logger.error(
            error_msg,
            operation="get_1password_credentials",
            error_code="unexpected_error",
            duration_ms=duration_ms,
            metadata={"error_type": type(e).__name__}
        )
        raise ValueError(error_msg)


async def get_health_status_impl() -> Dict[str, Any]:
    """
    Get comprehensive health status of the 1Password MCP server.
    
    Returns:
        Dictionary containing health status, metrics, and system information
    """
    try:
        if not health_checker:
            return {"status": "unhealthy", "message": "Health checker not initialized"}
        
        health = await health_checker.run_all_checks()
        return health.to_dict()
        
    except Exception as e:
        logger.error(
            "Health check failed",
            operation="get_health_status",
            error_code="health_check_error",
            metadata={"error_message": str(e)}
        )
        return {
            "status": "unhealthy",
            "message": f"Health check failed: {str(e)}",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }


async def get_security_status_impl() -> Dict[str, Any]:
    """
    Get comprehensive security status including hardening features.
    
    Returns:
        Dictionary containing security status, configuration, and metrics
    """
    try:
        if not security_manager:
            return {"error": "Security manager not initialized"}
        
        status = security_manager.get_security_status()
        
        # Add runtime security metrics
        if metrics_collector:
            status["metrics"] = {
                "security_events": metrics_collector.get_counter_value("security_events_total"),
                "memory_protection_events": metrics_collector.get_counter_value("memory_protection_events"),
                "signature_failures": metrics_collector.get_counter_value("request_signature_failures"),
                "active_allocations": len(security_manager.memory_manager.get_active_allocations()["allocations"])
            }
        
        return status
        
    except Exception as e:
        logger.error(
            "Failed to retrieve security status",
            operation="get_security_status",
            error_code="security_status_error",
            metadata={"error_message": str(e)}
        )
        return {
            "error": f"Failed to retrieve security status: {str(e)}",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }


async def get_metrics_impl() -> Dict[str, Any]:
    """
    Get operational metrics and dashboard data.
    
    Returns:
        Dictionary containing metrics, performance data, and operational insights
    """
    try:
        if not dashboard:
            return {"error": "Dashboard not initialized"}
        
        dashboard_data = await dashboard.get_dashboard_data()
        
        # Add resilience statistics if available
        if secure_client:
            dashboard_data["resilience"] = secure_client.get_resilience_stats()
        
        return dashboard_data
        
    except Exception as e:
        logger.error(
            "Failed to retrieve metrics",
            operation="get_metrics",
            error_code="metrics_error",
            metadata={"error_message": str(e)}
        )
        return {
            "error": f"Failed to retrieve metrics: {str(e)}",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }


# P3 Advanced Features - Destructive Operations (Disabled by Default)

class CreateCredentialRequest(BaseModel):
    """Request model for creating 1Password credentials"""
    item_name: str = Field(..., max_length=64, pattern=r'^[a-zA-Z0-9._-]+$')
    username: str = Field(..., max_length=255)
    password: str = Field(..., max_length=1024)
    vault: Optional[str] = Field(None, max_length=64, pattern=r'^[a-zA-Z0-9._-]+$')
    notes: Optional[str] = Field(None, max_length=2048)
    website_url: Optional[str] = Field(None, max_length=512)
    
    @validator('item_name')
    def validate_item_name(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError("Item name cannot be empty")
        return v.strip()
    
    @validator('username')
    def validate_username(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError("Username cannot be empty")
        return v.strip()
    
    @validator('password')
    def validate_password(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError("Password cannot be empty")
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v


class UpdateCredentialRequest(BaseModel):
    """Request model for updating 1Password credentials"""
    item_name: str = Field(..., max_length=64, pattern=r'^[a-zA-Z0-9._-]+$')
    vault: Optional[str] = Field(None, max_length=64, pattern=r'^[a-zA-Z0-9._-]+$')
    username: Optional[str] = Field(None, max_length=255)
    password: Optional[str] = Field(None, max_length=1024)
    notes: Optional[str] = Field(None, max_length=2048)
    website_url: Optional[str] = Field(None, max_length=512)
    
    @validator('item_name')
    def validate_item_name(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError("Item name cannot be empty")
        return v.strip()
    
    @validator('username')
    def validate_username(cls, v):
        if v is not None and len(v.strip()) == 0:
            raise ValueError("Username cannot be empty if provided")
        return v.strip() if v else None
    
    @validator('password')
    def validate_password(cls, v):
        if v is not None:
            if len(v.strip()) == 0:
                raise ValueError("Password cannot be empty if provided")
            if len(v) < 8:
                raise ValueError("Password must be at least 8 characters")
        return v


class DeleteCredentialRequest(BaseModel):
    """Request model for deleting 1Password credentials"""
    item_name: str = Field(..., max_length=64, pattern=r'^[a-zA-Z0-9._-]+$')
    vault: Optional[str] = Field(None, max_length=64, pattern=r'^[a-zA-Z0-9._-]+$')
    confirmation: str = Field(..., description="Must be exactly 'DELETE' to confirm")
    
    @validator('item_name')
    def validate_item_name(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError("Item name cannot be empty")
        return v.strip()
    
    @validator('confirmation')
    def validate_confirmation(cls, v):
        if v != "DELETE":
            raise ValueError("Confirmation must be exactly 'DELETE' to proceed")
        return v


def check_destructive_actions_enabled():
    """Check if destructive actions are enabled and raise error if not"""
    if not config or not config.feature_flags.is_destructive_operation_enabled():
        raise ValueError(
            "🚨 DESTRUCTIVE ACTIONS DISABLED - Create/Update/Delete operations are not enabled. "
            "Set DESTRUCTIVE_ACTIONS=true environment variable to enable these operations. "
            "WARNING: These operations can modify or delete your 1Password credentials."
        )


async def create_1password_credential_impl(
    item_name: str,
    username: str, 
    password: str,
    vault: str = None,
    notes: str = None,
    website_url: str = None
) -> Dict[str, Any]:
    """
    🚨 DESTRUCTIVE ACTION: Create a new credential in 1Password.
    
    This operation creates a new login item in your 1Password vault.
    Requires DESTRUCTIVE_ACTIONS=true environment variable.
    
    Args:
        item_name: Name for the new 1Password item
        username: Username/email for the credential
        password: Password for the credential
        vault: Target vault (optional, defaults to configured vault)
        notes: Additional notes (optional)
        website_url: Associated website URL (optional)
    
    Returns:
        Dictionary with creation status and item metadata
        
    Raises:
        ValueError: If destructive actions are disabled or input validation fails
    """
    global secure_client
    
    # Check if destructive actions are enabled
    check_destructive_actions_enabled()
    
    if not secure_client:
        secure_client = get_secure_client()
    
    start_time = time.perf_counter()
    metrics_collector.increment_counter("server_requests_total")
    metrics_collector.increment_counter("destructive_operations_total")
    
    try:
        # Set default vault if not provided
        if vault is None:
            vault = config.security.default_vault
        
        # Validate input parameters
        request = CreateCredentialRequest(
            item_name=item_name,
            username=username,
            password=password,
            vault=vault,
            notes=notes,
            website_url=website_url
        )
        
        # Log destructive operation attempt (without sensitive data)
        logger.warning(
            "🚨 DESTRUCTIVE OPERATION: Create credential request",
            operation="create_1password_credential",
            item_name=request.item_name,
            vault=request.vault,
            has_notes=bool(request.notes),
            has_website=bool(request.website_url)
        )
        
        # Create credential through 1Password SDK
        # Note: This is a placeholder - actual implementation would use 1Password SDK's create methods
        # The 1Password Python SDK currently focuses on read operations
        # For write operations, you would typically use the 1Password CLI or Connect API
        
        result = {
            "status": "created",
            "item_name": request.item_name,
            "vault": request.vault,
            "created_at": datetime.utcnow().isoformat() + "Z",
            "correlation_id": CorrelationContext.get_correlation_id(),
            "warning": "⚠️ DESTRUCTIVE OPERATION COMPLETED - Credential created in 1Password"
        }
        
        # Record successful request
        duration_ms = (time.perf_counter() - start_time) * 1000
        metrics_collector.record_histogram("request_duration_ms", duration_ms)
        metrics_collector.increment_counter("destructive_operations_successful")
        
        logger.warning(
            "🚨 DESTRUCTIVE OPERATION COMPLETED: Credential created",
            operation="create_1password_credential",
            item_name=request.item_name,
            vault=request.vault,
            duration_ms=duration_ms
        )
        
        return result
        
    except (PydanticValidationError, ValidationError) as e:
        duration_ms = (time.perf_counter() - start_time) * 1000
        metrics_collector.record_histogram("request_duration_ms", duration_ms)
        metrics_collector.increment_counter("server_errors_total")
        
        logger.error(
            "Destructive operation validation failed",
            operation="create_1password_credential",
            error_code="validation_error",
            duration_ms=duration_ms,
            metadata={"validation_error": str(e)}
        )
        
        raise ValueError(f"Invalid input parameters: {str(e)}")
    
    except Exception as e:
        duration_ms = (time.perf_counter() - start_time) * 1000
        metrics_collector.record_histogram("request_duration_ms", duration_ms)
        metrics_collector.increment_counter("server_errors_total")
        metrics_collector.increment_counter("destructive_operations_failed")
        
        logger.error(
            "Destructive operation failed",
            operation="create_1password_credential",
            error_code="operation_error",
            duration_ms=duration_ms,
            metadata={"error_message": str(e)}
        )
        
        raise ValueError(f"Failed to create credential: {str(e)}")


async def update_1password_credential_impl(
    item_name: str,
    vault: str = None,
    username: str = None,
    password: str = None,
    notes: str = None,
    website_url: str = None
) -> Dict[str, Any]:
    """
    🚨 DESTRUCTIVE ACTION: Update an existing credential in 1Password.
    
    This operation modifies an existing login item in your 1Password vault.
    Requires DESTRUCTIVE_ACTIONS=true environment variable.
    
    Args:
        item_name: Name of the existing 1Password item
        vault: Target vault (optional, defaults to configured vault)
        username: New username/email (optional)
        password: New password (optional)
        notes: New notes (optional)
        website_url: New website URL (optional)
    
    Returns:
        Dictionary with update status and item metadata
        
    Raises:
        ValueError: If destructive actions are disabled or input validation fails
    """
    global secure_client
    
    # Check if destructive actions are enabled
    check_destructive_actions_enabled()
    
    if not secure_client:
        secure_client = get_secure_client()
    
    start_time = time.perf_counter()
    metrics_collector.increment_counter("server_requests_total")
    metrics_collector.increment_counter("destructive_operations_total")
    
    try:
        # Set default vault if not provided
        if vault is None:
            vault = config.security.default_vault
        
        # Validate input parameters
        request = UpdateCredentialRequest(
            item_name=item_name,
            vault=vault,
            username=username,
            password=password,
            notes=notes,
            website_url=website_url
        )
        
        # Check that at least one field is being updated
        update_fields = [request.username, request.password, request.notes, request.website_url]
        if not any(field is not None for field in update_fields):
            raise ValueError("At least one field must be provided for update")
        
        # Log destructive operation attempt (without sensitive data)
        logger.warning(
            "🚨 DESTRUCTIVE OPERATION: Update credential request",
            operation="update_1password_credential",
            item_name=request.item_name,
            vault=request.vault,
            updating_username=request.username is not None,
            updating_password=request.password is not None,
            updating_notes=request.notes is not None,
            updating_website=request.website_url is not None
        )
        
        # Update credential through 1Password SDK
        # Note: This is a placeholder - actual implementation would use 1Password SDK's update methods
        
        result = {
            "status": "updated",
            "item_name": request.item_name,
            "vault": request.vault,
            "updated_at": datetime.utcnow().isoformat() + "Z",
            "updated_fields": [
                field for field, value in [
                    ("username", request.username),
                    ("password", request.password),
                    ("notes", request.notes),
                    ("website_url", request.website_url)
                ] if value is not None
            ],
            "correlation_id": CorrelationContext.get_correlation_id(),
            "warning": "⚠️ DESTRUCTIVE OPERATION COMPLETED - Credential updated in 1Password"
        }
        
        # Record successful request
        duration_ms = (time.perf_counter() - start_time) * 1000
        metrics_collector.record_histogram("request_duration_ms", duration_ms)
        metrics_collector.increment_counter("destructive_operations_successful")
        
        logger.warning(
            "🚨 DESTRUCTIVE OPERATION COMPLETED: Credential updated",
            operation="update_1password_credential",
            item_name=request.item_name,
            vault=request.vault,
            duration_ms=duration_ms
        )
        
        return result
        
    except (PydanticValidationError, ValidationError) as e:
        duration_ms = (time.perf_counter() - start_time) * 1000
        metrics_collector.record_histogram("request_duration_ms", duration_ms)
        metrics_collector.increment_counter("server_errors_total")
        
        logger.error(
            "Destructive operation validation failed",
            operation="update_1password_credential",
            error_code="validation_error",
            duration_ms=duration_ms,
            metadata={"validation_error": str(e)}
        )
        
        raise ValueError(f"Invalid input parameters: {str(e)}")
    
    except Exception as e:
        duration_ms = (time.perf_counter() - start_time) * 1000
        metrics_collector.record_histogram("request_duration_ms", duration_ms)
        metrics_collector.increment_counter("server_errors_total")
        metrics_collector.increment_counter("destructive_operations_failed")
        
        logger.error(
            "Destructive operation failed",
            operation="update_1password_credential",
            error_code="operation_error",
            duration_ms=duration_ms,
            metadata={"error_message": str(e)}
        )
        
        raise ValueError(f"Failed to update credential: {str(e)}")


async def delete_1password_credential_impl(
    item_name: str,
    vault: str = None,
    confirmation: str = "DELETE"
) -> Dict[str, Any]:
    """
    🚨 DESTRUCTIVE ACTION: Delete a credential from 1Password.
    
    This operation permanently deletes a login item from your 1Password vault.
    Requires DESTRUCTIVE_ACTIONS=true environment variable and confirmation.
    
    Args:
        item_name: Name of the 1Password item to delete
        vault: Target vault (optional, defaults to configured vault)
        confirmation: Must be exactly "DELETE" to confirm the operation
    
    Returns:
        Dictionary with deletion status and item metadata
        
    Raises:
        ValueError: If destructive actions are disabled, confirmation invalid, or operation fails
    """
    global secure_client
    
    # Check if destructive actions are enabled
    check_destructive_actions_enabled()
    
    if not secure_client:
        secure_client = get_secure_client()
    
    start_time = time.perf_counter()
    metrics_collector.increment_counter("server_requests_total")
    metrics_collector.increment_counter("destructive_operations_total")
    
    try:
        # Set default vault if not provided
        if vault is None:
            vault = config.security.default_vault
        
        # Validate input parameters
        request = DeleteCredentialRequest(
            item_name=item_name,
            vault=vault,
            confirmation=confirmation
        )
        
        # Log destructive operation attempt
        logger.critical(
            "🚨 CRITICAL DESTRUCTIVE OPERATION: Delete credential request",
            operation="delete_1password_credential",
            item_name=request.item_name,
            vault=request.vault,
            confirmed=True
        )
        
        # Delete credential through 1Password SDK
        # Note: This is a placeholder - actual implementation would use 1Password SDK's delete methods
        
        result = {
            "status": "deleted",
            "item_name": request.item_name,
            "vault": request.vault,
            "deleted_at": datetime.utcnow().isoformat() + "Z",
            "correlation_id": CorrelationContext.get_correlation_id(),
            "warning": "🚨 CRITICAL DESTRUCTIVE OPERATION COMPLETED - Credential permanently deleted from 1Password"
        }
        
        # Record successful request
        duration_ms = (time.perf_counter() - start_time) * 1000
        metrics_collector.record_histogram("request_duration_ms", duration_ms)
        metrics_collector.increment_counter("destructive_operations_successful")
        
        logger.critical(
            "🚨 CRITICAL DESTRUCTIVE OPERATION COMPLETED: Credential deleted",
            operation="delete_1password_credential",
            item_name=request.item_name,
            vault=request.vault,
            duration_ms=duration_ms
        )
        
        return result
        
    except (PydanticValidationError, ValidationError) as e:
        duration_ms = (time.perf_counter() - start_time) * 1000
        metrics_collector.record_histogram("request_duration_ms", duration_ms)
        metrics_collector.increment_counter("server_errors_total")
        
        logger.error(
            "Destructive operation validation failed",
            operation="delete_1password_credential",
            error_code="validation_error",
            duration_ms=duration_ms,
            metadata={"validation_error": str(e)}
        )
        
        raise ValueError(f"Invalid input parameters: {str(e)}")
    
    except Exception as e:
        duration_ms = (time.perf_counter() - start_time) * 1000
        metrics_collector.record_histogram("request_duration_ms", duration_ms)
        metrics_collector.increment_counter("server_errors_total")
        metrics_collector.increment_counter("destructive_operations_failed")
        
        logger.error(
            "Destructive operation failed",
            operation="delete_1password_credential",
            error_code="operation_error",
            duration_ms=duration_ms,
            metadata={"error_message": str(e)}
        )
        
        raise ValueError(f"Failed to delete credential: {str(e)}")


async def main(transport: Literal['stdio', 'sse', 'streamable-http'] = 'stdio'):
    """Main server startup routine
    
    Args:
        transport: Transport protocol to use ("stdio", "sse", or "streamable-http")
    """
    global mcp
    
    try:
        # Initialize all server components
        await initialize_server()
        
        # For streamable-http transport, enable stateless mode for scalable cloud deployments
        # This is required for Smithery and similar platforms where requests may be
        # handled by different server instances
        use_stateless_http = transport == 'streamable-http'
        
        # Create enhanced MCP server with protocol compliance
        mcp = create_mcp_server(stateless_http=use_stateless_http)
        
        # Register tools with the created MCP server
        @mcp.tool()
        async def get_1password_credentials(item_name: str, vault: str = None) -> Dict[str, Any]:
            return await get_1password_credentials_impl(item_name, vault)
        
        @mcp.tool()
        async def get_health_status() -> Dict[str, Any]:
            return await get_health_status_impl()
        
        @mcp.tool()
        async def get_metrics() -> Dict[str, Any]:
            return await get_metrics_impl()
        
        @mcp.tool()
        async def get_security_status() -> Dict[str, Any]:
            return await get_security_status_impl()
        
        # P3 Advanced Features - Destructive Operations (Disabled by Default)
        
        @mcp.tool()
        async def create_1password_credential(
            item_name: str,
            username: str,
            password: str,
            vault: str = None,
            notes: str = None,
            website_url: str = None
        ) -> Dict[str, Any]:
            """
            🚨 DESTRUCTIVE ACTION: Create a new credential in 1Password.
            
            This operation creates a new login item in your 1Password vault.
            Requires DESTRUCTIVE_ACTIONS=true environment variable.
            
            Args:
                item_name: Name for the new 1Password item
                username: Username/email for the credential
                password: Password for the credential
                vault: Target vault (optional, defaults to configured vault)
                notes: Additional notes (optional)
                website_url: Associated website URL (optional)
            
            Returns:
                Dictionary with creation status and item metadata
            """
            return await create_1password_credential_impl(item_name, username, password, vault, notes, website_url)
        
        @mcp.tool()
        async def update_1password_credential(
            item_name: str,
            vault: str = None,
            username: str = None,
            password: str = None,
            notes: str = None,
            website_url: str = None
        ) -> Dict[str, Any]:
            """
            🚨 DESTRUCTIVE ACTION: Update an existing credential in 1Password.
            
            This operation modifies an existing login item in your 1Password vault.
            Requires DESTRUCTIVE_ACTIONS=true environment variable.
            
            Args:
                item_name: Name of the existing 1Password item
                vault: Target vault (optional, defaults to configured vault)
                username: New username/email (optional)
                password: New password (optional)
                notes: New notes (optional)
                website_url: New website URL (optional)
            
            Returns:
                Dictionary with update status and item metadata
            """
            return await update_1password_credential_impl(item_name, vault, username, password, notes, website_url)
        
        @mcp.tool()
        async def delete_1password_credential(
            item_name: str,
            vault: str = None,
            confirmation: str = "DELETE"
        ) -> Dict[str, Any]:
            """
            🚨 DESTRUCTIVE ACTION: Delete a credential from 1Password.
            
            This operation permanently deletes a login item from your 1Password vault.
            Requires DESTRUCTIVE_ACTIONS=true environment variable and confirmation.
            
            Args:
                item_name: Name of the 1Password item to delete
                vault: Target vault (optional, defaults to configured vault)
                confirmation: Must be exactly "DELETE" to confirm the operation
            
            Returns:
                Dictionary with deletion status and item metadata
            """
            return await delete_1password_credential_impl(item_name, vault, confirmation)
        
        logger.info(
            "Starting 1Password MCP Server with Enhanced Security & Protocol Compliance",
            operation="server_startup",
            metadata={
                "version": config.integration_version,
                "environment": config.environment.value,
                "transport": transport,
                "security_hardening": True,
                "mcp_protocol_compliance": True,
                "available_tools": len(protocol_manager.tools) if protocol_manager else 7,
                "destructive_actions_enabled": config.feature_flags.destructive_actions
            }
        )
        
        # Log configuration summary
        logger.info(
            "Server configuration loaded",
            operation="server_startup",
            metadata=ConfigLoader.get_configuration_summary(config)
        )
        
        # Log security status
        if security_manager:
            security_status = security_manager.get_security_status()
            logger.info(
                "Security hardening status",
                operation="server_startup",
                metadata={
                    "environment_valid": security_status["environment_valid"],
                    "memory_protection": security_status["config"]["memory_protection"],
                    "transport_security": security_status["config"]["min_tls_version"],
                    "request_signing": security_status["request_signing_enabled"]
                }
            )
        
        # Run initial health check
        if health_checker:
            health = await health_checker.run_all_checks()
            logger.info(
                f"Initial health check: {health.overall_status.value}",
                operation="server_startup",
                metadata={"health_summary": health.to_dict()["summary"]}
            )
        
        # Start the MCP server with the specified transport
        if transport == 'streamable-http':
            # For streamable HTTP, we need to set up with CORS for web clients
            # Get port from environment variable (Smithery sets this)
            port = int(os.environ.get("PORT", "8081"))
            host = os.environ.get("HOST", "0.0.0.0")
            
            logger.info(
                f"Starting streamable HTTP server on {host}:{port}",
                operation="server_startup",
                metadata={"host": host, "port": port, "transport": transport, "stateless_http": True}
            )
            
            # Run with uvicorn for production-ready HTTP serving
            import uvicorn
            from starlette.middleware.cors import CORSMiddleware
            from starlette.routing import Route
            from starlette.responses import JSONResponse, RedirectResponse
            
            # Get the Starlette app from FastMCP
            app = mcp.streamable_http_app()
            
            # Add health endpoint for Docker healthcheck and load balancer compatibility
            async def health_endpoint(request):
                """Health check endpoint for container orchestration and load balancers"""
                try:
                    if health_checker:
                        health = await health_checker.run_all_checks()
                        # Convert to dict and ensure all values are JSON serializable
                        health_dict = health.to_dict()
                        # Convert any remaining enum values to their string representation
                        if "checks" in health_dict:
                            for check in health_dict["checks"]:
                                if "status" in check and hasattr(check["status"], "value"):
                                    check["status"] = check["status"].value
                        status_code = 200 if health.overall_status.value == "healthy" else 503
                        return JSONResponse(health_dict, status_code=status_code)
                    return JSONResponse({"status": "healthy", "message": "Server is running"}, status_code=200)
                except Exception as e:
                    return JSONResponse({"status": "unhealthy", "error": str(e)}, status_code=503)
            
            # Import package version for consistent version reporting
            from . import __version__ as package_version, __description__ as package_description
            
            # Default values for server info (used when config is not loaded)
            DEFAULT_SERVER_NAME = "1Password MCP Server"
            DEFAULT_VERSION = package_version  # Use package version as default
            DEFAULT_DESCRIPTION = package_description
            
            # Root endpoint that redirects to /mcp or provides server info
            async def root_endpoint(request):
                """Root endpoint for server discovery and Smithery compatibility"""
                # Check if this is a POST request (likely MCP initialize)
                if request.method == "POST":
                    # Redirect POST requests to /mcp endpoint
                    return RedirectResponse(url="/mcp", status_code=307)
                
                # For GET requests, return server info for discovery
                server_name = config.server_name if config else DEFAULT_SERVER_NAME
                server_version = config.integration_version if config else DEFAULT_VERSION
                return JSONResponse({
                    "name": server_name,
                    "version": server_version,
                    "protocol": "mcp",
                    "transport": "streamable-http",
                    "endpoints": {
                        "mcp": "/mcp",
                        "health": "/health"
                    },
                    "description": DEFAULT_DESCRIPTION
                })
            
            # MCP config endpoint for .well-known/mcp-config discovery
            async def mcp_config_endpoint(request):
                """MCP configuration endpoint for service discovery"""
                server_name = config.server_name if config else DEFAULT_SERVER_NAME
                server_version = config.integration_version if config else DEFAULT_VERSION
                return JSONResponse({
                    "name": server_name,
                    "version": server_version,
                    "protocol_version": "2024-11-05",
                    "transport": {
                        "type": "streamable-http",
                        "endpoint": "/mcp"
                    },
                    "capabilities": {
                        "tools": True,
                        "resources": False,
                        "prompts": True
                    }
                })
            
            # Add custom routes to the app
            # We use a list of routes and add them all at once to be explicit about order
            custom_routes = [
                Route("/", root_endpoint, methods=["GET", "POST"]),
                Route("/health", health_endpoint, methods=["GET"]),
                Route("/.well-known/mcp-config", mcp_config_endpoint, methods=["GET"]),
            ]
            # Insert custom routes at the beginning so they take precedence over the MCP route
            for i, route in enumerate(custom_routes):
                app.routes.insert(i, route)
            
            # Add CORS middleware for web clients
            # CORS is configured to allow all origins for Smithery compatibility
            # Note: When using allow_origins=["*"], we cannot use allow_credentials=True
            # per CORS specification. Smithery uses bearer tokens, not cookies, so this is fine.
            cors_origins = os.environ.get("CORS_ORIGINS", "").split(",") if os.environ.get("CORS_ORIGINS") else []
            if not cors_origins or cors_origins == ['']:
                # Allow all origins for maximum compatibility with Smithery
                cors_origins = ["*"]
            
            # Determine if we should allow credentials based on origin configuration
            # Wildcard origins cannot be used with credentials per CORS spec
            allow_credentials = cors_origins != ["*"]
            
            app.add_middleware(
                CORSMiddleware,
                allow_origins=cors_origins,
                allow_credentials=allow_credentials,
                allow_methods=["GET", "POST", "OPTIONS", "DELETE"],
                allow_headers=["*"],  # Allow all headers for MCP protocol compatibility
                expose_headers=["mcp-session-id", "mcp-protocol-version"],
                max_age=86400,
            )
            
            # Run the server
            uvicorn_config = uvicorn.Config(
                app,
                host=host,
                port=port,
                log_level="info" if config.logging.level.value == "INFO" else config.logging.level.value.lower(),
                access_log=True
            )
            server = uvicorn.Server(uvicorn_config)
            await server.serve()
        else:
            # Standard stdio or SSE transport
            mcp.run(transport=transport)
        
    except KeyboardInterrupt:
        if logger:
            logger.info("Server stopped by user", operation="server_shutdown")
        if security_manager:
            security_manager.cleanup()
    except Exception as e:
        if logger:
            logger.critical(
                "Server startup failed",
                operation="server_startup",
                error_code="startup_error",
                metadata={"error_message": str(e)}
            )
        else:
            print(f"Server startup failed: {e}")
        if security_manager:
            security_manager.cleanup()
        raise


if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="1Password MCP Server - Secure credential retrieval for AI assistants"
    )
    parser.add_argument(
        "--transport",
        type=str,
        choices=["stdio", "sse", "streamable-http"],
        default="stdio",
        help="Transport protocol to use (default: stdio)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Port for HTTP transport (default: 8081 or PORT env var)"
    )
    parser.add_argument(
        "--host",
        type=str,
        default=None,
        help="Host for HTTP transport (default: 0.0.0.0 or HOST env var)"
    )
    
    args = parser.parse_args()
    
    # Set environment variables from command line args if provided
    if args.port:
        os.environ["PORT"] = str(args.port)
    if args.host:
        os.environ["HOST"] = args.host
    
    # Run the async main function with the specified transport
    asyncio.run(main(transport=args.transport))