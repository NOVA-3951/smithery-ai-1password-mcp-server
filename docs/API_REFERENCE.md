# 1Password MCP Server - API Reference

## Table of Contents
- [Overview](#overview)
- [Tools](#tools)
- [Error Handling](#error-handling)
- [Response Formats](#response-formats)
- [Examples](#examples)
- [Rate Limiting](#rate-limiting)

## Overview

The 1Password MCP Server provides secure credential retrieval through the Model Context Protocol (MCP). All tools follow MCP conventions and provide comprehensive error handling, audit logging, and security controls.

### Base Configuration

- **Protocol**: MCP 1.6 compatible
- **Transport**: stdio (secure, no network exposure)
- **Authentication**: 1Password service account tokens
- **Rate Limiting**: Configurable (default: 10 requests/minute)
- **Audit Logging**: Complete request/response tracking

## Tools

### get_1password_credentials

Securely retrieve credentials from 1Password with comprehensive error handling and resilience patterns.

#### Parameters

| Parameter | Type | Required | Description | Validation |
|-----------|------|----------|-------------|------------|
| `item_name` | string | Yes | Name of the 1Password item | Alphanumeric, dots, hyphens, underscores only. Max 64 characters. |
| `vault` | string | No | Name of the 1Password vault | Defaults to configured vault. Same validation as item_name. |

#### Parameter Validation

**Item Name Constraints**:
- **Pattern**: `^[a-zA-Z0-9._-]+$`
- **Length**: 1-64 characters
- **Examples**: 
  - ✅ `github.com`
  - ✅ `database-prod`
  - ✅ `api_key_service`
  - ❌ `item with spaces`
  - ❌ `item@domain.com`
  - ❌ `<script>alert('xss')</script>`

**Vault Name Constraints**:
- **Pattern**: `^[a-zA-Z0-9._-]+$` 
- **Default**: Uses `SECURITY_DEFAULT_VAULT` environment variable
- **Examples**:
  - ✅ `AI`
  - ✅ `Production-Secrets`
  - ✅ `team_credentials`

#### Response Format

```json
{
  "username": "user@example.com",
  "password": "secure_password_here",
  "item_name": "github.com",
  "vault": "AI",
  "retrieved_at": "2024-01-15T10:30:00.000000",
  "correlation_id": "req-uuid-12345",
  "security_protected": true
}
```

#### Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `username` | string | Username/email from 1Password item |
| `password` | string | Password from 1Password item |
| `item_name` | string | Name of the requested item |
| `vault` | string | Vault where item was found |
| `retrieved_at` | string | ISO 8601 timestamp of retrieval |
| `correlation_id` | string | Unique request identifier for audit trails |
| `security_protected` | boolean | Whether security hardening features were applied |

#### Error Conditions

| Error Type | HTTP Equivalent | Description | Retry |
|------------|-----------------|-------------|-------|
| `ValueError` | 400 Bad Request | Invalid input parameters | No |
| `AuthenticationError` | 401 Unauthorized | 1Password authentication failed | No |
| `RateLimitError` | 429 Too Many Requests | Rate limit exceeded | Yes (after window) |
| `CircuitBreakerOpen` | 503 Service Unavailable | Service protection active | Yes (after timeout) |
| `TimeoutError` | 504 Gateway Timeout | Request timeout | Yes (with backoff) |

### get_health_status

Get comprehensive health status of the 1Password MCP server including all subsystems.

#### Parameters

None.

#### Response Format

```json
{
  "overall_status": "healthy",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "uptime_seconds": 3600,
  "summary": {
    "total_checks": 4,
    "healthy_checks": 4,
    "unhealthy_checks": 0
  },
  "checks": [
    {
      "name": "basic",
      "status": "healthy",
      "message": "System is operational",
      "duration_ms": 2.5
    },
    {
      "name": "onepassword_connectivity",
      "status": "healthy", 
      "message": "1Password API connectivity verified",
      "duration_ms": 150.2
    },
    {
      "name": "security_status",
      "status": "healthy",
      "message": "Security hardening active",
      "duration_ms": 5.1
    },
    {
      "name": "environment_security",
      "status": "healthy",
      "message": "Environment security validated",
      "duration_ms": 3.8
    }
  ]
}
```

#### Health Check Types

| Check Name | Purpose | Typical Duration |
|------------|---------|------------------|
| `basic` | System operational status | < 5ms |
| `onepassword_connectivity` | 1Password API reachability | < 500ms |
| `security_status` | Security hardening validation | < 10ms |
| `environment_security` | Environment configuration security | < 10ms |

### get_metrics

Get operational metrics, performance data, and security insights.

#### Parameters

None.

#### Response Format

```json
{
  "timestamp": "2024-01-15T10:30:00.000Z",
  "health": {
    "overall_status": "healthy",
    "summary": {
      "total_checks": 4,
      "healthy_checks": 4
    }
  },
  "metrics": {
    "server_requests_total": {
      "type": "counter",
      "current_value": 1250,
      "rate_per_minute": 5.2
    },
    "request_duration_ms": {
      "type": "histogram", 
      "current_value": 145.2,
      "percentiles": {
        "p50": 120.0,
        "p95": 280.0,
        "p99": 450.0
      }
    },
    "onepassword_requests_total": {
      "type": "counter",
      "current_value": 1200,
      "rate_per_minute": 5.0
    },
    "rate_limit_rejections_total": {
      "type": "counter", 
      "current_value": 15,
      "rate_per_minute": 0.1
    }
  },
  "resilience": {
    "circuit_breaker": {
      "state": "closed",
      "failure_count": 0,
      "success_count": 1200,
      "success_rate": 99.2,
      "last_failure_time": null
    },
    "retry_statistics": {
      "total_attempts": 1215,
      "successful_attempts": 1200,
      "failed_attempts": 15,
      "average_attempts_per_request": 1.01
    }
  }
}
```

#### Metric Types

| Type | Description | Example Use |
|------|-------------|-------------|
| `counter` | Monotonically increasing values | Request counts, error counts |
| `gauge` | Point-in-time values | Current connections, memory usage |
| `histogram` | Distribution of values | Response times, request sizes |

### get_security_status

Get comprehensive security status including hardening features.

#### Parameters

None.

#### Response Format

```json
{
  "environment_valid": true,
  "config": {
    "memory_protection": true,
    "transport_security": true,
    "request_signing": true,
    "environment_validation": true,
    "min_tls_version": "1.2"
  },
  "request_signing_enabled": true,
  "tls_enforcement_enabled": true,
  "metrics": {
    "security_events": 0,
    "memory_protection_events": 0,
    "signature_failures": 0,
    "active_allocations": 0
  }
}
```

## Error Handling

### Error Response Format

All tools return errors using MCP-standard ValueError with descriptive messages:

```json
{
  "error": {
    "type": "ValueError",
    "message": "Descriptive error message",
    "correlation_id": "req-uuid-12345"
  }
}
```

### Error Categories

#### 1. Input Validation Errors

**Causes**:
- Invalid item name format
- Item name too long
- Invalid vault name
- Missing required parameters

**Example**:
```
Invalid input parameters: Item name must contain only alphanumeric characters, periods, hyphens, and underscores
```

**Resolution**: Fix input parameters according to validation rules.

#### 2. Authentication Errors

**Causes**:
- Invalid service account token
- Expired token
- Insufficient permissions
- Network connectivity issues

**Example**:
```
Authentication failed: Invalid token
```

**Resolution**: Verify service account token and permissions.

#### 3. Rate Limiting Errors

**Causes**:
- Request rate exceeds configured limits
- Multiple concurrent clients
- Retry storms

**Example**:
```
Rate limit exceeded. Please try again later.
```

**Resolution**: Implement client-side rate limiting and exponential backoff.

#### 4. Service Availability Errors

**Causes**:
- Circuit breaker open due to failures
- 1Password service issues
- Network timeouts

**Example**:
```
Service is temporarily unavailable. Please try again later.
```

**Resolution**: Wait for circuit breaker recovery (default: 60 seconds).

## Response Formats

### Success Response

```json
{
  "result": {
    // Tool-specific response data
  }
}
```

### Error Response

```json
{
  "error": {
    "type": "ValueError",
    "message": "Human-readable error description",
    "correlation_id": "req-uuid-for-tracking"
  }
}
```

### Metadata Fields

All responses include:
- **timestamp**: ISO 8601 formatted timestamp
- **correlation_id**: Unique identifier for request tracking
- **duration_ms**: Request processing time (for performance monitoring)

## Examples

### Basic Credential Retrieval

```json
// Request
{
  "tool": "get_1password_credentials",
  "parameters": {
    "item_name": "github.com"
  }
}

// Response
{
  "result": {
    "username": "developer@company.com",
    "password": "ghp_secure_token_here",
    "item_name": "github.com", 
    "vault": "AI",
    "retrieved_at": "2024-01-15T10:30:00.000000",
    "correlation_id": "req-abc123",
    "security_protected": true
  }
}
```

### Credential Retrieval with Specific Vault

```json
// Request
{
  "tool": "get_1password_credentials",
  "parameters": {
    "item_name": "database-prod",
    "vault": "Infrastructure"
  }
}

// Response  
{
  "result": {
    "username": "db_admin",
    "password": "complex_db_password",
    "item_name": "database-prod",
    "vault": "Infrastructure", 
    "retrieved_at": "2024-01-15T10:31:00.000000",
    "correlation_id": "req-def456",
    "security_protected": true
  }
}
```

### Error Example - Invalid Item Name

```json
// Request
{
  "tool": "get_1password_credentials", 
  "parameters": {
    "item_name": "invalid item name!"
  }
}

// Response
{
  "error": {
    "type": "ValueError",
    "message": "Invalid input parameters: Item name must contain only alphanumeric characters, periods, hyphens, and underscores",
    "correlation_id": "req-ghi789"
  }
}
```

### Health Check Example

```json
// Request
{
  "tool": "get_health_status",
  "parameters": {}
}

// Response
{
  "result": {
    "overall_status": "healthy",
    "timestamp": "2024-01-15T10:30:00.000Z",
    "uptime_seconds": 3600,
    "summary": {
      "total_checks": 4,
      "healthy_checks": 4,
      "unhealthy_checks": 0
    },
    "checks": [
      {
        "name": "basic",
        "status": "healthy",
        "message": "System is operational",
        "duration_ms": 2.5
      }
    ]
  }
}
```

## Rate Limiting

### Default Limits

- **Requests**: 10 per minute (configurable)
- **Window**: 60 seconds (sliding window)
- **Burst**: No burst allowance (smooth rate limiting)

### Configuration

```bash
# Adjust rate limits via environment variables
export RATE_LIMIT_MAX_REQUESTS=20
export RATE_LIMIT_WINDOW_SECONDS=60
```

### Rate Limit Headers

Rate limiting information is included in error responses:

```json
{
  "error": {
    "type": "RateLimitError",
    "message": "Rate limit exceeded. Please try again later.",
    "details": {
      "limit": 10,
      "window_seconds": 60,
      "retry_after_seconds": 45
    }
  }
}
```

### Best Practices

1. **Implement Backoff**: Use exponential backoff for retries
2. **Cache Results**: Cache credentials when appropriate for your use case
3. **Monitor Usage**: Track request patterns to optimize limits
4. **Handle Errors**: Gracefully handle rate limit errors

### Example Rate Limit Handling

```python
import asyncio
import time

async def get_credentials_with_retry(item_name, max_retries=3):
    for attempt in range(max_retries):
        try:
            return await get_1password_credentials(item_name)
        except RateLimitError as e:
            if attempt == max_retries - 1:
                raise
            # Exponential backoff
            wait_time = (2 ** attempt) * 1.0
            await asyncio.sleep(wait_time)
```

---

For additional information:
- [Setup Guide](SETUP_GUIDE.md) - Installation and configuration
- [Security Guide](SECURITY_GUIDE.md) - Security considerations
- [Troubleshooting](TROUBLESHOOTING.md) - Common issues and solutions