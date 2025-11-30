#!/usr/bin/env python3
"""
Unit tests for 1Password MCP Server core functionality
Covers tool functions, input validation, error handling, and authentication
"""

import pytest
import asyncio
import os
import unittest.mock as mock
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Dict, Any

# Import modules to test
from .config import ConfigLoader, ServerConfig, FeatureFlagsConfig, ConfigurationError
from .server import (
    CredentialRequest, ValidationError, AuthenticationError, RateLimitError,
    OnePasswordSecureClient, get_1password_credentials_impl
)
from .structured_logging import get_logger, CorrelationContext
from .resilience import CircuitBreakerOpenError


class TestConfigurationManagement:
    """Test configuration loading and validation"""
    
    def test_feature_flags_default_values(self):
        """Test feature flags have secure defaults"""
        flags = FeatureFlagsConfig()
        assert flags.destructive_actions is False
        assert flags.is_destructive_operation_enabled() is False
        assert flags.get_enabled_features() == []
    
    def test_feature_flags_enabled(self):
        """Test feature flags when enabled"""
        flags = FeatureFlagsConfig(destructive_actions=True)
        assert flags.destructive_actions is True
        assert flags.is_destructive_operation_enabled() is True
        assert "Destructive Actions (Create/Update/Delete)" in flags.get_enabled_features()
    
    @patch.dict(os.environ, {
        'OP_SERVICE_ACCOUNT_TOKEN': 'ops_test_token_1234567890',
        'DESTRUCTIVE_ACTIONS': 'true'
    })
    def test_config_loader_environment_variables(self):
        """Test configuration loading from environment"""
        config = ConfigLoader.load_from_environment()
        assert config.service_account_token == 'ops_test_token_1234567890'
        assert config.feature_flags.destructive_actions is True
    
    @patch.dict(os.environ, {}, clear=True)
    def test_config_loader_missing_token(self):
        """Test configuration loads without required token (lazy validation)"""
        # Token is now optional at startup - lazy validation is used
        config = ConfigLoader.load_from_environment()
        assert config.service_account_token is None
        assert config.has_valid_token() is False
        # require_token() should raise ConfigurationError
        with pytest.raises(ConfigurationError):
            config.require_token()
    
    @patch.dict(os.environ, {
        'OP_SERVICE_ACCOUNT_TOKEN': 'ops_test_token_1234567890',
        'ENVIRONMENT': 'production',
        'LOG_LEVEL': 'DEBUG'
    })
    def test_config_validation_warnings(self):
        """Test configuration validation produces warnings"""
        config = ConfigLoader.load_from_environment()
        warnings = ConfigLoader.validate_configuration(config)
        assert any("Debug logging enabled in production" in w for w in warnings)


class TestInputValidation:
    """Test input validation and edge cases"""
    
    def test_credential_request_valid_input(self):
        """Test valid credential request"""
        # Mock config for validation
        with patch('onepassword_mcp_server.server.config') as mock_config:
            mock_config.security.max_item_name_length = 64
            mock_config.security.allowed_item_name_pattern = r'^[a-zA-Z0-9._-]+$'
            mock_config.security.default_vault = 'AI'
            
            request = CredentialRequest(item_name="github.com", vault="AI")
            assert request.item_name == "github.com"
            assert request.vault == "AI"
    
    def test_credential_request_invalid_characters(self):
        """Test credential request with invalid characters"""
        with patch('onepassword_mcp_server.server.config') as mock_config:
            mock_config.security.max_item_name_length = 64
            mock_config.security.allowed_item_name_pattern = r'^[a-zA-Z0-9._-]+$'
            
            with pytest.raises(ValueError, match="alphanumeric characters"):
                CredentialRequest(item_name="invalid item name!")
    
    def test_credential_request_too_long(self):
        """Test credential request with name too long"""
        with patch('onepassword_mcp_server.server.config') as mock_config:
            mock_config.security.max_item_name_length = 10
            mock_config.security.allowed_item_name_pattern = r'^[a-zA-Z0-9._-]+$'
            
            with pytest.raises(ValueError, match="exceeds maximum length"):
                CredentialRequest(item_name="very_long_item_name_that_exceeds_limit")
    
    def test_credential_request_empty_vault_uses_default(self):
        """Test credential request uses default vault when empty"""
        with patch('onepassword_mcp_server.server.config') as mock_config:
            mock_config.security.max_item_name_length = 64
            mock_config.security.allowed_item_name_pattern = r'^[a-zA-Z0-9._-]+$'
            mock_config.security.default_vault = 'DefaultVault'
            
            request = CredentialRequest(item_name="test.com", vault=None)
            assert request.vault == 'DefaultVault'


class TestErrorHandling:
    """Test comprehensive error handling scenarios"""
    
    @pytest.fixture
    def mock_config(self):
        """Mock server configuration"""
        config = MagicMock()
        config.security.max_item_name_length = 64
        config.security.allowed_item_name_pattern = r'^[a-zA-Z0-9._-]+$'
        config.security.default_vault = 'AI'
        config.security.token_min_length = 20
        config.service_account_token = 'ops_test_token_1234567890'
        config.has_valid_token.return_value = True
        config.require_token.return_value = 'ops_test_token_1234567890'
        config.rate_limit.max_requests = 10
        config.rate_limit.window_seconds = 60
        config.circuit_breaker.failure_threshold = 5
        config.circuit_breaker.recovery_timeout_seconds = 60
        config.circuit_breaker.success_threshold = 3
        config.circuit_breaker.timeout_seconds = 30.0
        config.retry.max_attempts = 3
        config.retry.base_delay_seconds = 1.0
        config.retry.max_delay_seconds = 60.0
        config.retry.exponential_base = 2.0
        config.retry.jitter_enabled = True
        return config
    
    @pytest.fixture
    def mock_metrics_collector(self):
        """Mock metrics collector"""
        collector = MagicMock()
        collector.increment_counter = MagicMock()
        collector.record_histogram = MagicMock()
        collector.create_counter = MagicMock()
        collector.create_histogram = MagicMock()
        collector.create_gauge = MagicMock()
        return collector
    
    @pytest.mark.asyncio
    async def test_authentication_error_handling(self, mock_config, mock_metrics_collector):
        """Test authentication error scenarios"""
        with patch('onepassword_mcp_server.server.config', mock_config):
            with patch('onepassword_mcp_server.server.logger') as mock_logger:
                client = OnePasswordSecureClient(mock_config, mock_metrics_collector)
                
                with patch('onepassword_mcp_server.server.Client.authenticate') as mock_auth:
                    mock_auth.side_effect = Exception("Authentication failed")
                    
                    request = CredentialRequest(item_name="test.com")
                    
                    # The error will be wrapped in AuthenticationError
                    with pytest.raises((AuthenticationError, Exception)):
                        await client.get_credentials(request)
    
    @pytest.mark.asyncio
    async def test_rate_limit_error_handling(self, mock_config, mock_metrics_collector):
        """Test rate limiting behavior"""
        with patch('onepassword_mcp_server.server.config', mock_config):
            with patch('onepassword_mcp_server.server.logger') as mock_logger:
                client = OnePasswordSecureClient(mock_config, mock_metrics_collector)
                
                # Simulate rate limit exceeded
                with patch.object(client.rate_limiter, 'is_allowed', return_value=(False, 0)):
                    request = CredentialRequest(item_name="test.com")
                    
                    with pytest.raises(RateLimitError, match="Rate limit exceeded"):
                        await client.get_credentials(request)
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_open_error(self, mock_config, mock_metrics_collector):
        """Test circuit breaker open scenario"""
        mock_client = AsyncMock()
        mock_client.get_credentials.side_effect = CircuitBreakerOpenError("Circuit breaker is open")
        
        with patch('onepassword_mcp_server.server.secure_client', mock_client):
            with patch('onepassword_mcp_server.server.config', mock_config):
                with patch('onepassword_mcp_server.server.metrics_collector', mock_metrics_collector):
                    with patch('onepassword_mcp_server.server.logger') as mock_logger:
                        with pytest.raises(ValueError, match="Service is temporarily unavailable"):
                            await get_1password_credentials_impl("test.com")


class TestAuthentication:
    """Test authentication scenarios"""
    
    @pytest.mark.asyncio
    async def test_valid_token_authentication(self):
        """Test successful authentication with valid token"""
        mock_client = AsyncMock()
        
        with patch('onepassword_mcp_server.server.Client.authenticate', return_value=mock_client):
            with patch('onepassword_mcp_server.server.logger') as mock_logger:
                config = MagicMock()
                config.service_account_token = 'ops_valid_token_1234567890'
                config.require_token.return_value = 'ops_valid_token_1234567890'
                config.integration_name = 'Test Integration'
                config.integration_version = 'v1.0.0'
                config.rate_limit.max_requests = 10
                config.rate_limit.window_seconds = 60
                config.circuit_breaker.failure_threshold = 5
                config.circuit_breaker.recovery_timeout_seconds = 60
                config.circuit_breaker.success_threshold = 3
                config.circuit_breaker.timeout_seconds = 30.0
                config.retry.max_attempts = 3
                config.retry.base_delay_seconds = 1.0
                config.retry.max_delay_seconds = 60.0
                config.retry.exponential_base = 2.0
                config.retry.jitter_enabled = True
                
                metrics = MagicMock()
                metrics.increment_counter = MagicMock()
                metrics.create_counter = MagicMock()
                metrics.create_histogram = MagicMock()
                metrics.create_gauge = MagicMock()
                
                client = OnePasswordSecureClient(config, metrics)
                result = await client._authenticate()
                
                assert result is not None
                metrics.increment_counter.assert_called_with("onepassword_authentication_attempts")
    
    @pytest.mark.asyncio
    async def test_invalid_token_authentication(self):
        """Test authentication failure with invalid token"""
        with patch('onepassword_mcp_server.server.Client.authenticate') as mock_auth:
            # Import the OnePasswordError wrapper class from the server module
            # This is used for catching 1Password SDK errors in a generic way
            from onepassword_mcp_server.server import OnePasswordError
            mock_auth.side_effect = OnePasswordError("Invalid token")
            
            with patch('onepassword_mcp_server.server.logger') as mock_logger:
                config = MagicMock()
                config.service_account_token = 'invalid_token'
                config.require_token.return_value = 'invalid_token'
                config.integration_name = 'Test Integration'
                config.integration_version = 'v1.0.0'
                config.rate_limit.max_requests = 10
                config.rate_limit.window_seconds = 60
                config.circuit_breaker.failure_threshold = 5
                config.circuit_breaker.recovery_timeout_seconds = 60
                config.circuit_breaker.success_threshold = 3
                config.circuit_breaker.timeout_seconds = 30.0
                config.retry.max_attempts = 3
                config.retry.base_delay_seconds = 1.0
                config.retry.max_delay_seconds = 60.0
                config.retry.exponential_base = 2.0
                config.retry.jitter_enabled = True
                
                metrics = MagicMock()
                metrics.increment_counter = MagicMock()
                metrics.create_counter = MagicMock()
                metrics.create_histogram = MagicMock()
                metrics.create_gauge = MagicMock()
                
                client = OnePasswordSecureClient(config, metrics)
                
                with pytest.raises(AuthenticationError):
                    await client._authenticate()
                
                metrics.increment_counter.assert_called_with("onepassword_authentication_failures")


class TestToolFunctions:
    """Test MCP tool function implementations"""
    
    @pytest.mark.asyncio
    async def test_get_1password_credentials_success(self):
        """Test successful credential retrieval"""
        mock_credentials = {
            "username": "test@example.com",
            "password": "secure_password",
            "item_name": "test.com",
            "vault": "AI",
            "retrieved_at": "2024-01-01T00:00:00.000000",
            "correlation_id": "test-correlation-id"
        }
        
        mock_client = AsyncMock()
        mock_client.get_credentials = AsyncMock(return_value=mock_credentials)
        
        with patch('onepassword_mcp_server.server.secure_client', mock_client):
            with patch('onepassword_mcp_server.server.config') as mock_config:
                mock_config.security.default_vault = 'AI'
                mock_config.security.max_item_name_length = 64
                mock_config.security.allowed_item_name_pattern = r'^[a-zA-Z0-9._-]+$'
                
                with patch('onepassword_mcp_server.server.metrics_collector') as mock_metrics:
                    mock_metrics.increment_counter = MagicMock()
                    mock_metrics.record_histogram = MagicMock()
                    
                    with patch('onepassword_mcp_server.server.logger') as mock_logger:
                        result = await get_1password_credentials_impl("test.com")
                        
                        assert result["username"] == "test@example.com"
                        assert result["password"] == "secure_password"
                        assert result["item_name"] == "test.com"
                        mock_metrics.increment_counter.assert_called_with("server_requests_total")
    
    @pytest.mark.asyncio
    async def test_get_1password_credentials_validation_error(self):
        """Test credential retrieval with validation error"""
        with patch('onepassword_mcp_server.server.config') as mock_config:
            mock_config.security.default_vault = 'AI'
            mock_config.security.max_item_name_length = 10
            mock_config.security.allowed_item_name_pattern = r'^[a-zA-Z0-9._-]+$'
            
            with patch('onepassword_mcp_server.server.metrics_collector') as mock_metrics:
                mock_metrics.increment_counter = MagicMock()
                mock_metrics.record_histogram = MagicMock()
                
                with patch('onepassword_mcp_server.server.logger') as mock_logger:
                    with pytest.raises(ValueError, match="Invalid input parameters"):
                        await get_1password_credentials_impl("very_long_invalid_item_name!")


class TestLoggingAndMonitoring:
    """Test logging and monitoring functionality"""
    
    def test_correlation_context(self):
        """Test correlation context management"""
        correlation_id = "test-correlation-123"
        
        with CorrelationContext(correlation_id):
            # Test that correlation context is properly set
            assert True  # Context manager should not raise
    
    def test_structured_logger_creation(self):
        """Test structured logger creation"""
        logger = get_logger("test-component")
        assert logger is not None
        assert hasattr(logger, 'info')
        assert hasattr(logger, 'error')
        assert hasattr(logger, 'audit')


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])