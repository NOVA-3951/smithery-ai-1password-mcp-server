# 1Password MCP Server - Troubleshooting Guide

## Table of Contents
- [Quick Diagnostics](#quick-diagnostics)
- [Common Issues](#common-issues)
- [Error Messages](#error-messages)
- [Performance Issues](#performance-issues)
- [Advanced Troubleshooting](#advanced-troubleshooting)
- [Getting Help](#getting-help)

## Quick Diagnostics

### Health Check Commands

```bash
# 1. Test basic connectivity
python -c "
import asyncio
from onepassword_mcp_server.monitoring import basic_health_check
result = asyncio.run(basic_health_check())
print(f'Basic health: {result[\"status\"]}')
"

# 2. Test 1Password connectivity  
python -c "
import asyncio
from onepassword_mcp_server.monitoring import onepassword_connectivity_check
result = asyncio.run(onepassword_connectivity_check())
print(f'1Password connectivity: {result[\"status\"]}')
"

# 3. Test configuration loading
python -c "
from onepassword_mcp_server.config import ConfigLoader
try:
    config = ConfigLoader.load_from_environment()
    print('✓ Configuration loaded successfully')
    print(f'Environment: {config.environment.value}')
    print(f'Default vault: {config.security.default_vault}')
except Exception as e:
    print(f'✗ Configuration error: {e}')
"
```

### Log Analysis

```bash
# Enable debug logging
export LOG_LEVEL=DEBUG

# Run with verbose output
onepassword-mcp-server 2>&1 | tee debug.log

# Analyze common patterns
grep "ERROR" debug.log
grep "authentication" debug.log  
grep "rate_limit" debug.log
```

## Common Issues

### 1. Configuration Issues

#### Missing Service Account Token

**Symptoms**:
```
ConfigurationError: OP_SERVICE_ACCOUNT_TOKEN environment variable is required
```

**Diagnosis**:
```bash
# Check if token is set
echo $OP_SERVICE_ACCOUNT_TOKEN

# Check token format
echo $OP_SERVICE_ACCOUNT_TOKEN | cut -c1-4  # Should show "ops_"
```

**Solutions**:
```bash
# Set token in environment
export OP_SERVICE_ACCOUNT_TOKEN=ops_your_actual_token_here

# Or add to .env file
echo "OP_SERVICE_ACCOUNT_TOKEN=ops_your_token" >> .env

# Verify token format (should start with "ops_")
# Verify token length (should be 50+ characters)
```

#### Invalid Configuration Values

**Symptoms**:
```
ValueError: max_requests must be positive
ValueError: Invalid regex pattern: ...
```

**Solutions**:
```bash
# Check numeric values
export RATE_LIMIT_MAX_REQUESTS=10  # Must be > 0
export CIRCUIT_BREAKER_TIMEOUT=30.0  # Must be > 0

# Check pattern syntax
export SECURITY_ALLOWED_ITEM_NAME_PATTERN="^[a-zA-Z0-9._-]+$"
```

### 2. Authentication Issues

#### 1Password Authentication Failure

**Symptoms**:
```
AuthenticationError: Authentication failed: Invalid token
OnePasswordError: [401] Unauthorized
```

**Diagnosis**:
```bash
# Test token manually with 1Password CLI
op vault list --token=$OP_SERVICE_ACCOUNT_TOKEN

# Check token permissions
op item list --vault=AI --token=$OP_SERVICE_ACCOUNT_TOKEN
```

**Solutions**:
1. **Verify Token**: Ensure token is copied correctly without extra spaces
2. **Check Permissions**: Verify service account has vault access
3. **Token Expiry**: Check if token needs rotation
4. **Network Issues**: Verify internet connectivity to 1Password

#### Service Account Permissions

**Symptoms**:
```
Item 'example.com' not found in vault 'AI'
Permission denied accessing vault
```

**Solutions**:
1. **Vault Access**: Grant service account access to target vault
2. **Item Permissions**: Ensure read permissions on specific items
3. **Vault Name**: Verify vault name spelling and case sensitivity
4. **Item Name**: Check item exists and name is correct

### 3. Network and Connectivity Issues

#### Network Timeouts

**Symptoms**:
```
TimeoutError: Request timeout after 30.0 seconds
Circuit breaker is open, service unavailable
```

**Diagnosis**:
```bash
# Test network connectivity
curl -I https://my.1password.com
ping my.1password.com

# Check firewall rules
netstat -an | grep :443
```

**Solutions**:
```bash
# Increase timeout values
export CIRCUIT_BREAKER_TIMEOUT=60.0
export RETRY_MAX_DELAY=120.0

# Check proxy settings if applicable
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080
```

#### Rate Limiting Issues

**Symptoms**:
```
Rate limit exceeded. Please try again later.
Too many requests from client
```

**Solutions**:
```bash
# Adjust rate limiting
export RATE_LIMIT_MAX_REQUESTS=20
export RATE_LIMIT_WINDOW_SECONDS=60

# Check for multiple instances
ps aux | grep onepassword-mcp-server
```

### 4. Claude Integration Issues

#### MCP Server Not Recognized

**Symptoms**:
- Claude doesn't recognize 1Password server
- No credential retrieval functionality available

**Diagnosis**:
```bash
# Check Claude Desktop config location
# macOS: ~/Library/Application Support/Claude/claude_desktop_config.json  
# Windows: %APPDATA%/Claude/claude_desktop_config.json

# Verify config syntax
cat ~/Library/Application\ Support/Claude/claude_desktop_config.json | jq .
```

**Solutions**:
1. **Config Location**: Ensure config file is in correct location
2. **JSON Syntax**: Validate JSON format with `jq` or online validator
3. **Command Path**: Verify `onepassword-mcp-server` is in PATH
4. **Restart Claude**: Restart Claude Desktop after config changes

#### Transport Issues

**Symptoms**:
```
MCP transport error
Failed to establish stdio connection
```

**Solutions**:
```bash
# Test command directly
onepassword-mcp-server --help

# Check command path
which onepassword-mcp-server

# Test with full path
/usr/local/bin/onepassword-mcp-server --version
```

## Error Messages

### Authentication Errors

| Error Message | Cause | Solution |
|---------------|-------|----------|
| `Invalid token` | Wrong service account token | Verify token from 1Password console |
| `Unauthorized` | Insufficient permissions | Grant vault access to service account |
| `Token expired` | Service account token expired | Generate new token |
| `Authentication failed` | Network or service issue | Check connectivity and retry |

### Validation Errors

| Error Message | Cause | Solution |
|---------------|-------|----------|
| `Invalid input parameters` | Malformed item name | Use only alphanumeric, dots, hyphens, underscores |
| `Item name exceeds maximum length` | Name too long | Limit to 64 characters |
| `Item not found` | Missing item or wrong vault | Verify item exists in specified vault |
| `Vault name must contain only...` | Invalid vault name | Use allowed characters only |

### Service Errors

| Error Message | Cause | Solution |
|---------------|-------|----------|
| `Circuit breaker is open` | Multiple failures detected | Wait for recovery or check 1Password status |
| `Rate limit exceeded` | Too many requests | Reduce request frequency |
| `Service temporarily unavailable` | System overload | Wait and retry with backoff |
| `Configuration not loaded` | Missing configuration | Ensure environment variables are set |

## Performance Issues

### Slow Response Times

**Symptoms**:
- Credential retrieval takes > 5 seconds
- Health checks timing out
- High CPU or memory usage

**Diagnosis**:
```bash
# Monitor resource usage
top -p $(pgrep onepassword-mcp)
htop

# Check network latency
ping my.1password.com
curl -w "@curl-format.txt" -o /dev/null https://my.1password.com

# Analyze performance logs
grep "duration_ms" application.log | tail -20
```

**Solutions**:
```bash
# Optimize timeouts
export CIRCUIT_BREAKER_TIMEOUT=45.0
export RETRY_BASE_DELAY=0.5
export RETRY_MAX_DELAY=30.0

# Reduce retry attempts for faster failure
export RETRY_MAX_ATTEMPTS=2

# Enable performance profiling if needed
export ENABLE_PERFORMANCE_PROFILING=true  # Development only
```

### Memory Issues

**Symptoms**:
- High memory usage
- Out of memory errors
- Process crashes

**Solutions**:
```bash
# Monitor memory usage
ps aux | grep onepassword-mcp-server
valgrind --tool=memcheck onepassword-mcp-server  # Development

# Check for memory leaks in logs
grep -i "memory" application.log

# Restart service periodically if needed
systemctl restart onepassword-mcp-server
```

### High Error Rates

**Symptoms**:
- > 5% error rate in metrics
- Frequent circuit breaker activations
- Authentication failures

**Analysis**:
```bash
# Check error patterns
jq 'select(.level=="ERROR")' application.log | head -10

# Monitor circuit breaker state
python -c "
import asyncio
from onepassword_mcp_server.server import get_metrics_impl
result = asyncio.run(get_metrics_impl())
print('Circuit breaker state:', result.get('resilience', {}).get('circuit_breaker', {}))
"
```

## Advanced Troubleshooting

### Network Debugging

```bash
# Trace network calls
export LOG_LEVEL=DEBUG
strace -e trace=network onepassword-mcp-server

# Monitor network connections
netstat -an | grep onepassword
lsof -i -p $(pgrep onepassword-mcp)

# Test SSL/TLS connectivity
openssl s_client -connect my.1password.com:443
```

### Process Debugging

```bash
# Check process status
systemctl status onepassword-mcp-server

# Monitor file descriptors
lsof -p $(pgrep onepassword-mcp)

# Check environment variables
cat /proc/$(pgrep onepassword-mcp)/environ | tr '\0' '\n'

# Attach debugger (development)
gdb -p $(pgrep onepassword-mcp)
```

### Log Analysis

```bash
# Extract correlation IDs for request tracing
grep "correlation_id" application.log | jq -r '.correlation_id' | sort | uniq

# Analyze request patterns
jq 'select(.operation=="get_credentials") | .item_name' application.log | sort | uniq -c

# Monitor error trends
jq 'select(.level=="ERROR") | .timestamp' application.log | cut -c1-13 | uniq -c

# Performance analysis
jq 'select(.duration_ms) | .duration_ms' application.log | sort -n | tail -10
```

### Configuration Debugging

```bash
# Dump effective configuration
python -c "
from onepassword_mcp_server.config import ConfigLoader
import json
config = ConfigLoader.load_from_environment()
summary = ConfigLoader.get_configuration_summary(config)
print(json.dumps(summary, indent=2))
"

# Test feature flags
python -c "
from onepassword_mcp_server.config import ConfigLoader
config = ConfigLoader.load_from_environment()
flags = config.feature_flags
print(f'Write operations enabled: {flags.enable_write_operations}')
print(f'Enabled features: {flags.get_enabled_features()}')
"

# Validate environment variables
env | grep -E "(OP_|RATE_LIMIT|CIRCUIT_BREAKER|LOG_|MONITORING_|SECURITY_|ENABLE_)" | sort
```

## Getting Help

### Information to Collect

When seeking help, gather the following information:

1. **System Information**:
   ```bash
   # OS and Python version
   uname -a
   python3 --version
   pip show onepassword-mcp-server
   ```

2. **Configuration**:
   ```bash
   # Sanitized configuration (remove sensitive data)
   env | grep -E "(OP_|RATE_LIMIT|CIRCUIT_BREAKER)" | sed 's/OP_SERVICE_ACCOUNT_TOKEN=.*/OP_SERVICE_ACCOUNT_TOKEN=***REDACTED***/'
   ```

3. **Error Logs**:
   ```bash
   # Recent error messages
   tail -50 application.log | grep -E "(ERROR|CRITICAL)"
   ```

4. **Health Status**:
   ```bash
   # Current system health
   python -c "
   import asyncio
   from onepassword_mcp_server.server import get_health_status_impl
   result = asyncio.run(get_health_status_impl())
   print(result)
   "
   ```

### Support Channels

1. **GitHub Issues**: [Report bugs and feature requests](https://github.com/your-org/1password-mcp-server/issues)
2. **Documentation**: Check [Setup Guide](SETUP_GUIDE.md) and [Security Guide](SECURITY_GUIDE.md)
3. **Community**: Search existing issues for similar problems
4. **1Password Support**: For 1Password service account issues

### Best Practices

1. **Reproduce Issues**: Document steps to reproduce the problem
2. **Isolate Variables**: Test with minimal configuration
3. **Check Recent Changes**: Review recent configuration or environment changes
4. **Monitor Trends**: Use metrics to identify patterns over time
5. **Document Solutions**: Keep internal documentation of resolutions

---

For additional troubleshooting information:
- [Setup Guide](SETUP_GUIDE.md) - Installation and configuration
- [Security Guide](SECURITY_GUIDE.md) - Security-related issues  
- [API Documentation](API_REFERENCE.md) - Tool usage and parameters