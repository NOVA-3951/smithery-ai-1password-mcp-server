# 1Password MCP Server - Complete Setup Guide

## Table of Contents
- [Prerequisites](#prerequisites)
- [Installation Methods](#installation-methods)
- [Configuration](#configuration)
- [Deployment](#deployment)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)

## Prerequisites

### System Requirements
- **Python**: 3.12 or higher
- **Operating System**: Windows, macOS, or Linux
- **Memory**: Minimum 256MB RAM
- **Network**: Internet access for 1Password API calls

### 1Password Requirements
- **1Password Account**: Business or Enterprise plan
- **Service Account**: With appropriate vault permissions
- **Vault Access**: Read permissions to target vaults

## Installation Methods

### Method 1: PyPI Installation (Recommended)

```bash
# Install the package
pip install onepassword-mcp-server

# Verify installation
onepassword-mcp-server --help
```

### Method 2: From Source

```bash
# Clone the repository
git clone https://github.com/your-org/1password-mcp-server.git
cd 1password-mcp-server

# Install with uv (recommended)
uv sync

# Or install with pip
pip install -e .
```

### Method 3: Docker (Coming Soon)

```bash
# Pull the image
docker pull onepassword/mcp-server:latest

# Run with environment variables
docker run -e OP_SERVICE_ACCOUNT_TOKEN=ops_your_token onepassword/mcp-server
```

## Configuration

### Step 1: Create 1Password Service Account

1. **Access Developer Console**:
   - Go to [1Password Developer Console](https://my.1password.com/developer-tools/)
   - Sign in with your 1Password account

2. **Create Service Account**:
   - Click "Create Service Account"
   - Choose descriptive name: "MCP Server - [Environment]"
   - Save the token securely

3. **Configure Vault Access**:
   - Select target vaults (e.g., "AI", "Credentials")
   - Grant "Read" permissions
   - For write operations: Grant "Read/Write" permissions

### Step 2: Environment Configuration

Create a `.env` file:

```bash
# Required: 1Password Service Account Token
OP_SERVICE_ACCOUNT_TOKEN=ops_your_service_account_token_here

# Environment (development, staging, production)
ENVIRONMENT=production

# Security Settings
SECURITY_DEFAULT_VAULT=AI
RATE_LIMIT_MAX_REQUESTS=10
RATE_LIMIT_WINDOW_SECONDS=60

# Feature Flags
ENABLE_WRITE_OPERATIONS=false  # Enable with caution

# Logging Configuration
LOG_LEVEL=INFO
LOG_FORMAT=json

# Monitoring
MONITORING_HEALTH_CHECK_ENABLED=true
MONITORING_METRICS_ENABLED=true
```

### Step 3: Claude Desktop Configuration

Add to your `claude_desktop_config.json`:

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

**Alternative for development:**

```json
{
  "mcpServers": {
    "1Password": {
      "command": "uv",
      "args": [
        "run",
        "--with", "onepassword-mcp-server",
        "onepassword-mcp-server"
      ],
      "env": {
        "OP_SERVICE_ACCOUNT_TOKEN": "ops_your_token_here"
      }
    }
  }
}
```

## Deployment

### Development Environment

```bash
# Set environment variables
export OP_SERVICE_ACCOUNT_TOKEN=ops_your_token
export ENVIRONMENT=development
export LOG_LEVEL=DEBUG

# Run the server
onepassword-mcp-server
```

### Production Environment

1. **Security Checklist**:
   - [ ] Use dedicated service account for production
   - [ ] Limit vault access to minimum required
   - [ ] Enable audit logging
   - [ ] Configure rate limiting
   - [ ] Set up monitoring

2. **Environment Variables**:
   ```bash
   export OP_SERVICE_ACCOUNT_TOKEN=ops_production_token
   export ENVIRONMENT=production
   export LOG_LEVEL=WARNING
   export RATE_LIMIT_MAX_REQUESTS=5
   export MONITORING_HEALTH_CHECK_ENABLED=true
   ```

3. **Process Management**:
   ```bash
   # Using systemd (Linux)
   sudo systemctl enable onepassword-mcp-server
   sudo systemctl start onepassword-mcp-server

   # Using supervisor
   supervisord -c supervisord.conf
   ```

### High Availability Setup

For production environments requiring high availability:

1. **Load Balancer Configuration**:
   - Health check endpoint: `/health`
   - Timeout: 30 seconds
   - Retry: 3 attempts

2. **Multiple Instances**:
   ```bash
   # Instance 1
   export SERVER_NAME="1Password MCP Server - Instance 1"
   onepassword-mcp-server --port 8001

   # Instance 2  
   export SERVER_NAME="1Password MCP Server - Instance 2"
   onepassword-mcp-server --port 8002
   ```

## Verification

### Test Installation

```bash
# Check version
onepassword-mcp-server --version

# Test configuration
python -c "
from onepassword_mcp_server.config import ConfigLoader
config = ConfigLoader.load_from_environment()
print('Configuration loaded successfully')
print(f'Environment: {config.environment.value}')
print(f'Default vault: {config.security.default_vault}')
"
```

### Test 1Password Connectivity

```bash
# Health check
python -c "
import asyncio
from onepassword_mcp_server.monitoring import onepassword_connectivity_check
result = asyncio.run(onepassword_connectivity_check())
print(f'1Password connectivity: {result[\"status\"]}')
"
```

### Test Claude Integration

1. **Launch Claude Desktop**
2. **Test credential retrieval**:
   ```
   "Get my login credentials for github.com"
   ```
3. **Test health monitoring**:
   ```
   "Check the health status of the 1Password server"
   ```

## Troubleshooting

### Common Issues

#### 1. Authentication Failures

**Symptoms**:
```
ConfigurationError: OP_SERVICE_ACCOUNT_TOKEN environment variable is required
```

**Solutions**:
- Verify token is set: `echo $OP_SERVICE_ACCOUNT_TOKEN`
- Check token format: Should start with `ops_`
- Verify token permissions in 1Password console

#### 2. Vault Access Denied

**Symptoms**:
```
Item 'example.com' not found in vault 'AI'
```

**Solutions**:
- Verify vault exists and is accessible
- Check service account permissions
- Confirm item name spelling and format

#### 3. Rate Limiting

**Symptoms**:
```
Rate limit exceeded. Please try again later.
```

**Solutions**:
- Wait for rate limit window to reset
- Increase `RATE_LIMIT_MAX_REQUESTS` if appropriate
- Implement client-side rate limiting

#### 4. Circuit Breaker Open

**Symptoms**:
```
Service is temporarily unavailable. Please try again later.
```

**Solutions**:
- Wait for circuit breaker recovery (default: 60 seconds)
- Check 1Password service status
- Review error logs for underlying issues

### Advanced Troubleshooting

#### Enable Debug Logging

```bash
export LOG_LEVEL=DEBUG
onepassword-mcp-server
```

#### Test Individual Components

```bash
# Test configuration loading
python -c "
from onepassword_mcp_server.config import ConfigLoader
try:
    config = ConfigLoader.load_from_environment()
    print('✓ Configuration loaded successfully')
except Exception as e:
    print(f'✗ Configuration error: {e}')
"

# Test 1Password authentication
python -c "
import asyncio
from onepassword_mcp_server.server import OnePasswordSecureClient
from onepassword_mcp_server.config import ConfigLoader
from onepassword_mcp_server.monitoring import MetricsCollector

async def test_auth():
    config = ConfigLoader.load_from_environment()
    metrics = MetricsCollector()
    client = OnePasswordSecureClient(config, metrics)
    try:
        await client._authenticate()
        print('✓ 1Password authentication successful')
    except Exception as e:
        print(f'✗ Authentication error: {e}')

asyncio.run(test_auth())
"
```

#### Performance Monitoring

```bash
# Check metrics
python -c "
import asyncio
from onepassword_mcp_server.server import get_metrics_impl
result = asyncio.run(get_metrics_impl())
print('Current metrics:', result)
"
```

### Getting Help

1. **Check Logs**: Review application logs for detailed error information
2. **Health Status**: Use health check endpoints for system status
3. **Documentation**: Review [Security Policy](../SECURITY.md) for security-related issues
4. **Community**: Check GitHub issues for similar problems
5. **Support**: Contact support with logs and configuration details

## Next Steps

After successful setup:

1. **Review Security**: Read the [Security Guide](SECURITY_GUIDE.md)
2. **Configure Monitoring**: Set up log aggregation and alerting
3. **Test Backup**: Verify credential access during outages
4. **Performance Tuning**: Adjust rate limits and timeouts for your use case
5. **Documentation**: Document your specific deployment configuration

---

For additional configuration options, see the [Configuration Reference](CONFIG_REFERENCE.md).
For security considerations, see the [Security Guide](SECURITY_GUIDE.md).