#!/usr/bin/env python3
"""
Configuration management and validation for the 1Password MCP Server
Includes environment validation, configuration parsing, and operational settings
"""

import os
import re
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from enum import Enum
import logging


class LogLevel(Enum):
    """Supported log levels"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class Environment(Enum):
    """Deployment environments"""
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


@dataclass
class RateLimitConfig:
    """Rate limiting configuration"""
    max_requests: int = 10
    window_seconds: int = 60
    
    def __post_init__(self):
        if self.max_requests <= 0:
            raise ValueError("max_requests must be positive")
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be positive")


@dataclass
class CircuitBreakerConfig:
    """Circuit breaker configuration"""
    failure_threshold: int = 5
    recovery_timeout_seconds: int = 60
    success_threshold: int = 3
    timeout_seconds: float = 30.0
    
    def __post_init__(self):
        if self.failure_threshold <= 0:
            raise ValueError("failure_threshold must be positive")
        if self.recovery_timeout_seconds <= 0:
            raise ValueError("recovery_timeout_seconds must be positive")
        if self.success_threshold <= 0:
            raise ValueError("success_threshold must be positive")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")


@dataclass
class RetryConfig:
    """Retry logic configuration"""
    max_attempts: int = 3
    base_delay_seconds: float = 1.0
    max_delay_seconds: float = 60.0
    exponential_base: float = 2.0
    jitter_enabled: bool = True
    
    def __post_init__(self):
        if self.max_attempts <= 0:
            raise ValueError("max_attempts must be positive")
        if self.base_delay_seconds <= 0:
            raise ValueError("base_delay_seconds must be positive")
        if self.max_delay_seconds <= 0:
            raise ValueError("max_delay_seconds must be positive")
        if self.exponential_base <= 1:
            raise ValueError("exponential_base must be greater than 1")


@dataclass
class SecurityConfig:
    """Security configuration"""
    max_item_name_length: int = 64
    allowed_item_name_pattern: str = r'^[a-zA-Z0-9._-]+$'
    default_vault: str = "AI"
    token_min_length: int = 20
    token_prefix: str = "ops_"
    
    def __post_init__(self):
        if self.max_item_name_length <= 0:
            raise ValueError("max_item_name_length must be positive")
        try:
            re.compile(self.allowed_item_name_pattern)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern: {e}")
        if self.token_min_length <= 0:
            raise ValueError("token_min_length must be positive")


@dataclass
class LoggingConfig:
    """Logging configuration"""
    level: LogLevel = LogLevel.INFO
    format: str = "json"  # json or text
    include_correlation_id: bool = True
    audit_enabled: bool = True
    performance_logging_enabled: bool = True
    log_scrubbing_enabled: bool = True
    
    def __post_init__(self):
        if self.format not in ["json", "text"]:
            raise ValueError("format must be 'json' or 'text'")


@dataclass
class MonitoringConfig:
    """Monitoring and health check configuration"""
    health_check_enabled: bool = True
    health_check_timeout_seconds: float = 30.0
    metrics_collection_enabled: bool = True
    metrics_retention_samples: int = 1000
    dashboard_enabled: bool = True
    
    def __post_init__(self):
        if self.health_check_timeout_seconds <= 0:
            raise ValueError("health_check_timeout_seconds must be positive")
        if self.metrics_retention_samples <= 0:
            raise ValueError("metrics_retention_samples must be positive")


@dataclass
class FeatureFlagsConfig:
    """Feature flags for enabling/disabling functionality"""
    # Destructive operations (disabled by default for security)
    destructive_actions: bool = False
    
    def __post_init__(self):
        # Warn if destructive operations are enabled
        if self.destructive_actions:
            import logging
            logging.warning("🚨 DESTRUCTIVE ACTIONS ENABLED - Create/Update/Delete operations are available. Ensure proper access controls are in place.")
    
    def get_enabled_features(self) -> List[str]:
        """Get list of enabled feature names"""
        enabled = []
        if self.destructive_actions:
            enabled.append("Destructive Actions (Create/Update/Delete)")
        return enabled
    
    def is_destructive_operation_enabled(self) -> bool:
        """Check if destructive operations are enabled"""
        return self.destructive_actions
    
    @property
    def enable_write_operations(self) -> bool:
        """Legacy property for backward compatibility"""
        return self.destructive_actions


@dataclass
class ServerConfig:
    """Complete server configuration"""
    # Environment
    environment: Environment = Environment.DEVELOPMENT
    
    # 1Password integration
    service_account_token: Optional[str] = None
    integration_name: str = "1Password MCP Integration"
    integration_version: str = "v1.1.0"
    
    # Feature configurations
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    circuit_breaker: CircuitBreakerConfig = field(default_factory=CircuitBreakerConfig)
    retry: RetryConfig = field(default_factory=RetryConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)
    feature_flags: FeatureFlagsConfig = field(default_factory=FeatureFlagsConfig)
    
    # Server settings
    server_name: str = "1Password MCP Server"
    server_description: str = "Secure credential retrieval for AI assistants"
    
    # Token validation state (internal)
    _token_validated: bool = field(default=False, repr=False, compare=False)
    
    def __post_init__(self):
        # Validate service account token if provided
        # Token is now optional at startup to allow MCP protocol initialization
        # Token will be validated lazily when credential operations are called
        if self.service_account_token:
            self._validate_token()
    
    def _validate_token(self) -> None:
        """Validate the service account token format"""
        if not self.service_account_token:
            return
        
        if len(self.service_account_token) < self.security.token_min_length:
            raise ValueError(f"Service account token must be at least {self.security.token_min_length} characters")
        
        if not self.service_account_token.startswith(self.security.token_prefix):
            logging.warning(f"Service account token does not start with expected prefix '{self.security.token_prefix}'")
        
        self._token_validated = True
    
    def _is_token_length_valid(self) -> bool:
        """Check if token meets minimum length requirement"""
        return (self.service_account_token is not None and 
                len(self.service_account_token) >= self.security.token_min_length)
    
    def has_valid_token(self) -> bool:
        """Check if a valid service account token is configured"""
        return bool(self.service_account_token) and (
            self._token_validated or self._is_token_length_valid()
        )
    
    def require_token(self) -> str:
        """Get the token, raising an error if not configured
        
        This method should be called when a credential operation is performed.
        
        Returns:
            The service account token
            
        Raises:
            ConfigurationError: If no token is configured
        """
        if not self.service_account_token:
            raise ConfigurationError(
                "OP_SERVICE_ACCOUNT_TOKEN environment variable is required for credential operations. "
                "Please configure your 1Password service account token."
            )
        
        # Validate token if not already validated
        if not self._token_validated:
            self._validate_token()
        
        return self.service_account_token



class ConfigurationError(Exception):
    """Configuration validation error"""
    pass


class ConfigLoader:
    """Configuration loader and validator"""
    
    @staticmethod
    def load_from_environment() -> ServerConfig:
        """Load configuration from environment variables"""
        try:
            # Environment
            env_name = os.getenv("ENVIRONMENT", "development").lower()
            try:
                environment = Environment(env_name)
            except ValueError:
                logging.warning(f"Unknown environment '{env_name}', defaulting to development")
                environment = Environment.DEVELOPMENT
            
            # 1Password token
            service_account_token = os.getenv("OP_SERVICE_ACCOUNT_TOKEN")
            
            # Rate limiting
            rate_limit = RateLimitConfig(
                max_requests=int(os.getenv("RATE_LIMIT_MAX_REQUESTS", "10")),
                window_seconds=int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
            )
            
            # Circuit breaker
            circuit_breaker = CircuitBreakerConfig(
                failure_threshold=int(os.getenv("CIRCUIT_BREAKER_FAILURE_THRESHOLD", "5")),
                recovery_timeout_seconds=int(os.getenv("CIRCUIT_BREAKER_RECOVERY_TIMEOUT", "60")),
                success_threshold=int(os.getenv("CIRCUIT_BREAKER_SUCCESS_THRESHOLD", "3")),
                timeout_seconds=float(os.getenv("CIRCUIT_BREAKER_TIMEOUT", "30.0"))
            )
            
            # Retry configuration
            retry = RetryConfig(
                max_attempts=int(os.getenv("RETRY_MAX_ATTEMPTS", "3")),
                base_delay_seconds=float(os.getenv("RETRY_BASE_DELAY", "1.0")),
                max_delay_seconds=float(os.getenv("RETRY_MAX_DELAY", "60.0")),
                exponential_base=float(os.getenv("RETRY_EXPONENTIAL_BASE", "2.0")),
                jitter_enabled=os.getenv("RETRY_JITTER_ENABLED", "true").lower() == "true"
            )
            
            # Security configuration
            security = SecurityConfig(
                max_item_name_length=int(os.getenv("SECURITY_MAX_ITEM_NAME_LENGTH", "64")),
                allowed_item_name_pattern=os.getenv("SECURITY_ALLOWED_ITEM_NAME_PATTERN", r'^[a-zA-Z0-9._-]+$'),
                default_vault=os.getenv("SECURITY_DEFAULT_VAULT", "AI"),
                token_min_length=int(os.getenv("SECURITY_TOKEN_MIN_LENGTH", "20")),
                token_prefix=os.getenv("SECURITY_TOKEN_PREFIX", "ops_")
            )
            
            # Logging configuration
            log_level_str = os.getenv("LOG_LEVEL", "INFO").upper()
            try:
                log_level = LogLevel(log_level_str)
            except ValueError:
                logging.warning(f"Unknown log level '{log_level_str}', defaulting to INFO")
                log_level = LogLevel.INFO
            
            logging_config = LoggingConfig(
                level=log_level,
                format=os.getenv("LOG_FORMAT", "json").lower(),
                include_correlation_id=os.getenv("LOG_INCLUDE_CORRELATION_ID", "true").lower() == "true",
                audit_enabled=os.getenv("LOG_AUDIT_ENABLED", "true").lower() == "true",
                performance_logging_enabled=os.getenv("LOG_PERFORMANCE_ENABLED", "true").lower() == "true",
                log_scrubbing_enabled=os.getenv("LOG_SCRUBBING_ENABLED", "true").lower() == "true"
            )
            
            # Monitoring configuration
            monitoring = MonitoringConfig(
                health_check_enabled=os.getenv("MONITORING_HEALTH_CHECK_ENABLED", "true").lower() == "true",
                health_check_timeout_seconds=float(os.getenv("MONITORING_HEALTH_CHECK_TIMEOUT", "30.0")),
                metrics_collection_enabled=os.getenv("MONITORING_METRICS_ENABLED", "true").lower() == "true",
                metrics_retention_samples=int(os.getenv("MONITORING_METRICS_RETENTION", "1000")),
                dashboard_enabled=os.getenv("MONITORING_DASHBOARD_ENABLED", "true").lower() == "true"
            )
            
            # Feature flags configuration
            feature_flags = FeatureFlagsConfig(
                destructive_actions=os.getenv("DESTRUCTIVE_ACTIONS", "false").lower() == "true"
            )
            
            # Create complete configuration
            config = ServerConfig(
                environment=environment,
                service_account_token=service_account_token,
                integration_name=os.getenv("OP_INTEGRATION_NAME", "1Password MCP Integration"),
                integration_version=os.getenv("OP_INTEGRATION_VERSION", "v1.1.0"),
                rate_limit=rate_limit,
                circuit_breaker=circuit_breaker,
                retry=retry,
                security=security,
                logging=logging_config,
                monitoring=monitoring,
                feature_flags=feature_flags,
                server_name=os.getenv("SERVER_NAME", "1Password MCP Server"),
                server_description=os.getenv("SERVER_DESCRIPTION", "Secure credential retrieval for AI assistants")
            )
            
            return config
            
        except ValueError as e:
            raise ConfigurationError(f"Configuration validation failed: {str(e)}")
        except Exception as e:
            raise ConfigurationError(f"Failed to load configuration: {str(e)}")
    
    @staticmethod
    def validate_configuration(config: ServerConfig) -> List[str]:
        """Validate configuration and return list of warnings"""
        warnings = []
        
        # Check if token is configured
        if not config.service_account_token:
            warnings.append("OP_SERVICE_ACCOUNT_TOKEN not configured - credential operations will fail")
        
        # Environment-specific validations
        if config.environment == Environment.PRODUCTION:
            if config.logging.level == LogLevel.DEBUG:
                warnings.append("Debug logging enabled in production environment")
            
            if config.rate_limit.max_requests > 100:
                warnings.append("High rate limit in production environment")
            
            if not config.monitoring.health_check_enabled:
                warnings.append("Health checks disabled in production environment")
            
            # In production, token should be configured
            if not config.service_account_token:
                warnings.append("Production environment without OP_SERVICE_ACCOUNT_TOKEN")
        
        # Security validations (only if token is configured)
        if config.service_account_token and len(config.service_account_token) < 50:
            warnings.append("Service account token appears short for production use")
        
        # Performance validations
        if config.circuit_breaker.timeout_seconds > 60:
            warnings.append("Circuit breaker timeout is very high")
        
        if config.retry.max_attempts > 5:
            warnings.append("High retry attempts may cause delays")
        
        # Monitoring validations
        if not config.monitoring.metrics_collection_enabled:
            warnings.append("Metrics collection is disabled")
        
        return warnings
    
    @staticmethod
    def get_configuration_summary(config: ServerConfig) -> Dict[str, Any]:
        """Get configuration summary for logging"""
        return {
            "environment": config.environment.value,
            "integration_name": config.integration_name,
            "integration_version": config.integration_version,
            "token_configured": config.has_valid_token(),
            "rate_limit": {
                "max_requests": config.rate_limit.max_requests,
                "window_seconds": config.rate_limit.window_seconds
            },
            "circuit_breaker": {
                "failure_threshold": config.circuit_breaker.failure_threshold,
                "recovery_timeout_seconds": config.circuit_breaker.recovery_timeout_seconds,
                "timeout_seconds": config.circuit_breaker.timeout_seconds
            },
            "retry": {
                "max_attempts": config.retry.max_attempts,
                "base_delay_seconds": config.retry.base_delay_seconds
            },
            "security": {
                "max_item_name_length": config.security.max_item_name_length,
                "default_vault": config.security.default_vault
            },
            "logging": {
                "level": config.logging.level.value,
                "format": config.logging.format,
                "audit_enabled": config.logging.audit_enabled
            },
            "monitoring": {
                "health_check_enabled": config.monitoring.health_check_enabled,
                "metrics_collection_enabled": config.monitoring.metrics_collection_enabled,
                "dashboard_enabled": config.monitoring.dashboard_enabled
            },
            "feature_flags": {
                "enabled_features": config.feature_flags.get_enabled_features(),
                "destructive_actions_enabled": config.feature_flags.destructive_actions
            }
        }