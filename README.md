# 1Password MCP Server - Enterprise Security & Full Protocol Compliance

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security](https://img.shields.io/badge/Security-Enterprise--Ready-green)](./SECURITY.md)
[![Version](https://img.shields.io/badge/Version-1.1.0-blue)](./pyproject.toml)
[![PyPI](https://img.shields.io/pypi/v/onepassword-mcp-server)](https://pypi.org/project/onepassword-mcp-server/)

A production-ready MCP server that provides secure access to 1Password credentials for AI assistants through the Model Context Protocol. Enhanced with enterprise-grade security hardening, comprehensive error handling, resilience patterns, monitoring capabilities, and full MCP protocol compliance.

## 🚀 Installation

### From PyPI (Recommended)

```bash
pip install onepassword-mcp-server
```

### From Source

```bash
git clone https://github.com/jon-the-dev/1password-mcp-server.git
cd mcp-server
pip install -e .
```

## 🆕 What's New in v1.0.0

### ✨ P1 Security Hardening

- **Memory Protection**: Secure credential lifecycle with automatic memory clearing
- **Transport Security**: TLS enforcement and secure cipher suite configuration
- **Request Signing**: Cryptographic integrity verification for all requests
- **Environment Validation**: Security posture validation and threat detection
- **CORS Configuration**: Secure cross-origin request handling

### 🛡️ P1 MCP Protocol Compliance

- **Enhanced Tool Discovery**: Comprehensive metadata and capability exposure
- **Resource Management**: Advanced resource exposure with caching strategies
- **Prompt Templates**: Pre-built templates for common credential operations
- **Multiple Transports**: Support for stdio, HTTP, and WebSocket transports
- **Backwards Compatibility**: Full compatibility with MCP versions 1.0, 1.1, and 1.6

### 🔧 P1 Error Handling & Resilience

- **Circuit Breaker Pattern**: Automatic service protection with configurable thresholds
- **Retry Logic**: Exponential backoff with jitter for failed requests
- **Timeout Handling**: Configurable request timeouts with graceful degradation
- **Comprehensive Error Classification**: Proper handling of retryable vs non-retryable errors

### 📊 P1 Logging & Monitoring

- **Structured JSON Logging**: Machine-readable logs with correlation IDs
- **Audit Logging**: Complete security event tracking with temporal data
- **Health Check Endpoints**: Real-time service health monitoring
- **Metrics Collection**: Request latency, error rates, and performance data
- **Sensitive Data Scrubbing**: Automatic credential data protection in logs

### Enhanced Configuration

- **Environment-Based Configuration**: Comprehensive settings management
- **Production Validation**: Environment-specific configuration validation
- **Operational Metrics**: Dashboard-ready performance and health data

## 🔒 Security Features

This server implements enterprise-grade security controls:

- **🛡️ Input Validation**: Pydantic-based validation with regex patterns
- **🔐 Authentication**: Service account token validation and format checking  
- **⚡ Rate Limiting**: Configurable rate limiting with metrics tracking
- **📝 Comprehensive Logging**: Structured security event logging with data scrubbing
- **🚨 Error Handling**: Secure error messages with circuit breaker protection
- **🎯 Principle of Least Privilege**: Vault-scoped access with configurable defaults
- **🔍 Monitoring**: Real-time health checks and performance metrics
- **⚙️ Resilience**: Circuit breaker and retry patterns for high availability

## ⚠️ Important Security Notice

This MCP server intentionally returns plaintext credentials to AI assistants. Security is achieved through:

- **Access Controls**: 1Password service account permissions
- **Network Isolation**: stdio transport only (no network exposure)
- **Input Sanitization**: Strict validation of all parameters
- **Audit Logging**: Complete request/response logging for security monitoring
- **Circuit Protection**: Automatic service protection against failures
- **Rate Limiting**: Configurable request throttling with monitoring

**📖 Read our [Security Policy](./SECURITY.md) before deploying to production.**

## 🚀 Quick Start

### Prerequisites

- Python 3.12 or higher
- `uv` package manager: `pip install uv`
- 1Password account with service account access
- Create a vault named `AI` (or configure custom vault)

### Installation

1. **Install dependencies**:

   ```bash
   uv sync
   ```

2. **Set up 1Password**:
   - Create a vault named `AI` in your 1Password account
   - Add credential items you want to access (use descriptive names like `ticktick.com`, `github.com`)
   - [Create a service account](https://my.1password.com/developer-tools/infrastructure-secrets/serviceaccount/)
   - Grant the service account `Read` access to your `AI` vault

3. **Configure Environment** (optional):

   ```bash
   cp .env.example .env
   # Edit .env with your preferred settings
   ```

4. **Configure Claude Desktop**:
   Add this configuration to your `claude_desktop_config.json`:

   ```json
   {
     "mcpServers": {
       "1Password": {
         "command": "onepassword-mcp-server",
         "env": {
           "OP_SERVICE_ACCOUNT_TOKEN": "ops_your_token_here"
         }
       }
     }
   }
   ```

   **Alternative for development setup**:

   ```json
   {
     "mcpServers": {
       "1Password": {
         "command": "uv",
         "args": [
           "run",
           "--with", "mcp[cli]",
           "--with", "onepassword-sdk",
           "--with", "pydantic",
           "--with", "cryptography",
           "mcp", "run",
           "/path/to/your/1password-mcp-server/onepassword_mcp_server/server.py"
         ],
         "env": {
           "OP_SERVICE_ACCOUNT_TOKEN": "ops_your_token_here"
         }
       }
     }
   }
   ```

5. **Test the integration**:
   Launch Claude and try: *"Get 1Password credentials for ticktick.com"*

### Installing via Smithery

```bash
npx -y @smithery/cli install @dkvdm/onepassword-mcp-server --client claude
```

## 🛠️ Configuration

### Environment Variables

| Variable | Required | Description | Default | Example |
|----------|----------|-------------|---------|---------|
| `OP_SERVICE_ACCOUNT_TOKEN` | ✅ | 1Password service account token | - | `ops_...` |
| `ENVIRONMENT` | ❌ | Deployment environment | `development` | `production` |
| `LOG_LEVEL` | ❌ | Logging level | `INFO` | `DEBUG`, `WARNING` |
| `LOG_FORMAT` | ❌ | Log output format | `json` | `text` |
| `RATE_LIMIT_MAX_REQUESTS` | ❌ | Rate limit threshold | `10` | `5` |
| `RATE_LIMIT_WINDOW_SECONDS` | ❌ | Rate limit window | `60` | `30` |
| `CIRCUIT_BREAKER_FAILURE_THRESHOLD` | ❌ | Circuit breaker threshold | `5` | `3` |
| `CIRCUIT_BREAKER_TIMEOUT` | ❌ | Request timeout (seconds) | `30.0` | `60.0` |
| `RETRY_MAX_ATTEMPTS` | ❌ | Maximum retry attempts | `3` | `2` |
| `SECURITY_DEFAULT_VAULT` | ❌ | Default vault name | `AI` | `Credentials` |

See `.env.example` for complete configuration options.

### Configuration Validation

The server automatically validates configuration on startup and provides warnings for:

- Production environment with debug logging enabled
- Unusually high rate limits or timeouts
- Missing monitoring configurations
- Security configuration issues

### Input Validation

Item names and vault names must match this pattern: `^[a-zA-Z0-9._-]+$`

**✅ Valid examples**: `ticktick.com`, `github-personal`, `email_provider`, `service.example`
**❌ Invalid examples**: `tick tick`, `site@domain`, `item/path`, `<script>`

## 🔧 API Reference

### `get_1password_credentials(item_name, vault="AI")`

Securely retrieves credentials from 1Password with comprehensive error handling.

**Parameters**:

- `item_name` (str): Name of the credential item (validated, required)
- `vault` (str): Vault name (defaults to configured default, validated)

**Returns**:

```json
{
  "username": "user@example.com",
  "password": "secure_password",
  "item_name": "ticktick.com",
  "vault": "AI",
  "retrieved_at": "2024-01-15T10:30:00.000Z",
  "correlation_id": "uuid-for-tracing"
}
```

**Enhanced Features**:

- Circuit breaker protection against API failures
- Automatic retry with exponential backoff
- Rate limiting with detailed metrics
- Comprehensive audit logging
- Performance timing and monitoring

### `get_health_status()`

Returns comprehensive health status and system information.

**Returns**:

```json
{
  "overall_status": "healthy",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "uptime_seconds": 3600,
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
      "message": "1Password connectivity check passed",
      "duration_ms": 150.2
    }
  ]
}
```

### `get_metrics()`

Returns detailed operational metrics and dashboard data.

**Returns**:

```json
{
  "timestamp": "2024-01-15T10:30:00.000Z",
  "health": { /* health status data */ },
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
    }
  },
  "resilience": {
    "circuit_breaker": {
      "state": "closed",
      "success_rate": 99.2
    }
  }
}
```

## 🤖 Use Cases

### Basic Credential Retrieval

```
"Get my login credentials for github.com"
```

### Health Monitoring

```
"Check the health status of the 1Password server"
```

### Performance Monitoring

```
"Show me the performance metrics for the credential service"
```

### Browser Automation Integration

Combine with [mcp-browser-use](https://github.com/Saik0s/mcp-browser-use):

```json
{
  "mcpServers": {
    "1Password": { /* configuration above */ },
    "browser-use": {
      "command": "uv",
      "args": ["--directory", "/path/to/mcp-browser-use", "run", "mcp-server-browser-use"],
      "env": {
        "MCP_USE_OWN_BROWSER": "true",
        "CHROME_CDP": "http://127.0.0.1:9222"
      }
    }
  }
}
```

Then use: *"Get 1Password credentials for ticktick.com and log into <https://ticktick.com/signin>"*

## 📊 Monitoring & Observability

### Structured Logging

The server provides comprehensive structured logging in JSON format:

```json
{
  "timestamp": "2024-01-15T10:30:00.000Z",
  "level": "INFO",
  "event_type": "audit",
  "correlation_id": "req-12345",
  "message": "Credential request initiated",
  "component": "1password-mcp-server",
  "operation": "get_credentials",
  "item_name": "github.com",
  "vault": "AI",
  "duration_ms": 145.2
}
```

### Log Categories

- **AUDIT**: Security-relevant events (credential access, authentication)
- **SECURITY**: Security violations (rate limits, invalid inputs)
- **PERFORMANCE**: Performance metrics and timing data
- **ERROR**: Error conditions and failure scenarios
- **ACCESS**: Request/response logging with correlation IDs

### Health Monitoring

The server includes built-in health checks:

- **Basic Health**: System operational status
- **1Password Connectivity**: Service account validation
- **Rate Limit Status**: Current rate limiting state
- **Circuit Breaker Status**: Resilience pattern health

### Metrics Collection

Comprehensive metrics tracking:

- **Request Metrics**: Total requests, error rates, success rates
- **Performance Metrics**: Response times, percentiles, throughput
- **Security Metrics**: Rate limit violations, authentication failures
- **Resilience Metrics**: Circuit breaker state, retry attempts

### Alert Conditions

Monitor these conditions for operational alerts:

- Error rate > 5% over 5 minutes
- P95 response time > 5 seconds
- Circuit breaker state = "open"
- Rate limit rejection rate > 10%
- Health check failures

## 🔍 Troubleshooting

### Common Issues

**Configuration Error**:

```
ConfigurationError: OP_SERVICE_ACCOUNT_TOKEN environment variable is required
```

**Solution**: Set the required environment variable with your service account token.

**Circuit Breaker Open**:

```
Service is temporarily unavailable. Please try again later.
```

**Solution**: Wait for the circuit breaker recovery timeout (default 60 seconds) or check 1Password service status.

**Rate Limit Exceeded**:

```
Rate limit exceeded. Please try again later.
```

**Solution**: Wait for the rate limit window to reset or adjust rate limit configuration.

**Health Check Failures**:

```
1Password connectivity check failed: Authentication failed
```

**Solution**: Verify service account token validity and permissions.

### Debug Mode

Enable debug logging:

```bash
export LOG_LEVEL=DEBUG
```

### Testing P1 Features

Run the comprehensive test suite:

```bash
python test_p1_features.py
```

## 🏗️ Architecture

### Core Components

- **ConfigLoader**: Environment-based configuration management
- **StructuredLogger**: JSON logging with correlation IDs and data scrubbing
- **ResilientOperationManager**: Circuit breaker and retry logic coordination
- **MetricsCollector**: Performance and operational metrics tracking
- **HealthChecker**: Health monitoring and status reporting
- **OnePasswordSecureClient**: Enhanced 1Password API client with resilience

### Resilience Patterns

- **Circuit Breaker**: Protects against cascading failures
- **Retry with Backoff**: Handles transient failures gracefully
- **Timeout Protection**: Prevents hanging requests
- **Rate Limiting**: Controls request volume and prevents abuse
- **Graceful Degradation**: Maintains functionality during partial failures

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🛡️ Security

Please read our [Security Policy](SECURITY.md) for information about:

- Supported versions
- Security model
- Vulnerability reporting
- Best practices
- P1 security enhancements

## 🤝 Contributing

1. Read the [Security Policy](SECURITY.md)
2. Follow secure coding practices
3. Include tests for new features (see `test_p1_features.py`)
4. Update documentation for security-relevant changes
5. Test resilience patterns and error handling

## 📋 Development & Testing

### Running Tests

```bash
# Run P1 feature tests
python test_p1_features.py

# Test configuration loading
python -c "from config import ConfigLoader; print(ConfigLoader.load_from_environment())"

# Test health checks
python -c "
import asyncio
from monitoring import basic_health_check
print(asyncio.run(basic_health_check()))
"
```

### Local Development

```bash
# Set up development environment
cp .env.example .env
export LOG_LEVEL=DEBUG
export ENVIRONMENT=development

# Run with enhanced logging
python server.py
```

---

**⚠️ Production Deployment**: Review the [Security Policy](SECURITY.md) and implement appropriate monitoring, access controls, and audit procedures. Consider the P1 enhancements for production reliability and observability.
