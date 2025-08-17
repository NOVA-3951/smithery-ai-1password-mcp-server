# Getting Started

This guide will help you quickly set up and configure the 1Password MCP Server with Claude Desktop.

## Prerequisites

Before starting, ensure you have:

- **Python 3.12 or higher** installed
- **1Password account** with vault access
- **Claude Desktop** application
- **Internet connection** for 1Password API access

## Step 1: Install the Server

### Option A: Install from PyPI (Recommended)

```bash
pip install onepassword-mcp-server
```

### Option B: Install from Source

```bash
git clone https://github.com/jon-the-dev/1password-mcp-server.git
cd 1password-mcp-server
pip install -e .
```

### Verify Installation

```bash
onepassword-mcp-server --version
# Should output: 1Password MCP Server v1.1.0
```

## Step 2: Create 1Password Service Account

1. **Access Developer Console**:
   - Go to [1Password Developer Console](https://developer.1password.com/)
   - Sign in with your 1Password account

2. **Create Service Account**:
   - Click "Create Service Account"
   - Name: `Claude AI Assistant`
   - Description: `MCP server for credential retrieval`

3. **Configure Vault Access**:
   - Grant access to specific vaults (recommended: create dedicated "AI" vault)
   - Select "Read" permissions
   - Note: Avoid granting access to personal or highly sensitive vaults

4. **Generate Token**:
   - Copy the service account token (starts with `ops_`)
   - Store securely - this token provides vault access

!!! warning "Security Note"
    The service account token provides read access to your 1Password vaults. Store it securely and never share it. Consider using a dedicated vault for AI-accessible credentials.

## Step 3: Configure Environment

### Set Environment Variables

```bash
# Required: 1Password service account token
export OP_SERVICE_ACCOUNT_TOKEN=ops_your_service_account_token_here

# Optional: Default vault name (defaults to first accessible vault)
export SECURITY_DEFAULT_VAULT=AI

# Optional: Environment specification
export ENVIRONMENT=production

# Optional: Adjust security settings
export RATE_LIMIT_MAX_REQUESTS=10
export CIRCUIT_BREAKER_TIMEOUT=60.0
```

### Using .env File (Alternative)

Create `.env` file in your project directory:

```bash
# 1Password Configuration
OP_SERVICE_ACCOUNT_TOKEN=ops_your_service_account_token_here
SECURITY_DEFAULT_VAULT=AI

# Server Configuration
ENVIRONMENT=production
LOG_LEVEL=INFO

# Security Settings
RATE_LIMIT_MAX_REQUESTS=10
RATE_LIMIT_WINDOW_SECONDS=60
CIRCUIT_BREAKER_FAILURE_THRESHOLD=5
CIRCUIT_BREAKER_TIMEOUT=60.0

# Feature Flags
ENABLE_WRITE_OPERATIONS=false  # Keep disabled for security
```

## Step 4: Configure Claude Desktop

### Locate Configuration File

The Claude Desktop configuration file location varies by operating system:

=== "macOS"
    ```
    ~/Library/Application Support/Claude/claude_desktop_config.json
    ```

=== "Windows"
    ```
    %APPDATA%/Claude/claude_desktop_config.json
    ```

=== "Linux"
    ```
    ~/.config/Claude/claude_desktop_config.json
    ```

### Add MCP Server Configuration

Edit or create the configuration file:

```json
{
  "mcpServers": {
    "onepassword": {
      "command": "onepassword-mcp-server",
      "env": {
        "OP_SERVICE_ACCOUNT_TOKEN": "ops_your_service_account_token_here",
        "SECURITY_DEFAULT_VAULT": "AI",
        "ENVIRONMENT": "production"
      }
    }
  }
}
```

### Advanced Configuration

For production deployments with custom settings:

```json
{
  "mcpServers": {
    "onepassword": {
      "command": "onepassword-mcp-server",
      "env": {
        "OP_SERVICE_ACCOUNT_TOKEN": "ops_your_service_account_token_here",
        "SECURITY_DEFAULT_VAULT": "AI",
        "ENVIRONMENT": "production",
        "LOG_LEVEL": "INFO",
        "RATE_LIMIT_MAX_REQUESTS": "20",
        "RATE_LIMIT_WINDOW_SECONDS": "60",
        "CIRCUIT_BREAKER_FAILURE_THRESHOLD": "5",
        "CIRCUIT_BREAKER_TIMEOUT": "60.0",
        "ENABLE_WRITE_OPERATIONS": "false"
      }
    }
  }
}
```

## Step 5: Test the Setup

### 1. Restart Claude Desktop

Close and reopen Claude Desktop to load the new configuration.

### 2. Verify MCP Server Recognition

In Claude, type:

> "Can you access my 1Password credentials?"

Claude should respond indicating that 1Password credential retrieval is available.

### 3. Test Credential Retrieval

Create a test item in your 1Password vault and try:

> "Please get my test-item credentials from 1Password"

### 4. Check Health Status

You can also ask Claude to check the server health:

> "What's the health status of the 1Password MCP server?"

## Step 6: Add Your Credentials

### Organize Your Vault

For best results, organize credentials in your 1Password vault:

1. **Use descriptive names**: `github.com`, `database-prod`, `api-key-service`
2. **Consistent naming**: Use hyphens or underscores consistently
3. **Avoid special characters**: Stick to alphanumeric, dots, hyphens, underscores
4. **Group related items**: Use vault organization features

### Example Vault Structure

```
AI Vault/
├── Development/
│   ├── github.com
│   ├── gitlab-personal
│   └── api-key-openai
├── Databases/
│   ├── postgres-dev
│   ├── redis-cache
│   └── mongodb-prod
└── Services/
    ├── aws-access-key
    ├── docker-registry
    └── npm-token
```

## Common Usage Patterns

### Development Workflow

> "Get my GitHub credentials and help me set up authentication for the new repository"

### Database Access

> "I need to connect to the production database. Get the postgres-prod credentials from 1Password"

### API Integration

> "Get my OpenAI API key so I can configure the application"

### Service Deployment

> "Get the Docker registry credentials for the deployment pipeline"

## Troubleshooting Quick Fixes

### MCP Server Not Recognized

1. **Check command path**: Ensure `onepassword-mcp-server` is in PATH
2. **Verify JSON syntax**: Use JSON validator for configuration file
3. **Restart Claude**: Close and reopen Claude Desktop
4. **Check logs**: Look for MCP connection errors

### Authentication Failures

1. **Verify token**: Check service account token format (starts with `ops_`)
2. **Check permissions**: Ensure service account has vault access
3. **Test manually**: Use 1Password CLI to verify token works
4. **Network connectivity**: Ensure internet access to 1Password

### Permission Errors

1. **Vault access**: Grant service account access to target vault
2. **Item permissions**: Verify read permissions on specific items
3. **Vault naming**: Check vault name spelling and case sensitivity

## Next Steps

- **[Security Guide](SECURITY_GUIDE.md)** - Review security best practices
- **[API Reference](API_REFERENCE.md)** - Learn about available tools and parameters
- **[Troubleshooting](TROUBLESHOOTING.md)** - Detailed troubleshooting guide
- **[Developer Guide](DEVELOPER_GUIDE.md)** - Contributing and development setup

## Need Help?

- **Issues**: [GitHub Issues](https://github.com/jon-the-dev/1password-mcp-server/issues)
- **Security**: [Security Policy](https://github.com/jon-the-dev/1password-mcp-server/security)
- **Documentation**: Complete guides available in this documentation

---

**Success!** Your 1Password MCP Server is now configured and ready to securely provide credentials to Claude.