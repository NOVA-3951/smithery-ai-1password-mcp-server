# 1Password MCP Server - Developer Guide

## Table of Contents
- [Architecture Overview](#architecture-overview)
- [Core Components](#core-components)
- [Development Setup](#development-setup)
- [Code Structure](#code-structure)
- [Contributing Guidelines](#contributing-guidelines)
- [Testing](#testing)
- [Release Process](#release-process)

## Architecture Overview

### High-Level Architecture

```
┌─────────────────┐    ┌──────────────────────────────────────┐    ┌─────────────────┐
│   AI Assistant  │    │         1Password MCP Server         │    │  1Password API  │
│   (Claude)      │────│                                      │────│  (Remote)       │
└─────────────────┘    └──────────────────────────────────────┘    └─────────────────┘
                                       │
                                       │
                       ┌───────────────┼───────────────┐
                       │               │               │
                   ┌───▼───┐      ┌────▼────┐      ┌───▼───┐
                   │ Tools │      │ Config  │      │  Log  │
                   │Layer  │      │Manager  │      │System │
                   └───────┘      └─────────┘      └───────┘
                       │               │               │
                   ┌───▼───┐      ┌────▼────┐      ┌───▼───┐
                   │Security│      │Resilience│     │Monitor│
                   │Hardening│     │Patterns │     │System │
                   └───────┘      └─────────┘      └───────┘
```

### Design Principles

1. **Security by Default**: All operations secure by default, explicit opt-in for risky features
2. **Fail-Safe Design**: System fails safely without exposing credentials
3. **Observable Operations**: Complete audit trail and monitoring capabilities
4. **Resilient Architecture**: Circuit breakers, retries, and graceful degradation
5. **Configuration-Driven**: Behavior controlled through environment variables

### Technology Stack

- **Language**: Python 3.12+
- **Framework**: FastMCP (Model Context Protocol)
- **Authentication**: 1Password SDK
- **Validation**: Pydantic 2.5+
- **Security**: Cryptography 41.0+
- **Testing**: pytest + pytest-asyncio
- **Build**: Hatchling

## Core Components

### 1. Configuration Management (`config.py`)

**Purpose**: Centralized configuration loading and validation

**Key Classes**:
- `ServerConfig`: Main configuration container
- `FeatureFlagsConfig`: Feature toggle management
- `SecurityConfig`: Security policy configuration
- `ConfigLoader`: Environment-based configuration loading

**Design Patterns**:
- **Dataclass Configuration**: Type-safe configuration with validation
- **Environment Variable Mapping**: 12-factor app compliance
- **Validation at Load Time**: Fail fast for invalid configurations

```python
@dataclass
class ServerConfig:
    environment: Environment = Environment.DEVELOPMENT
    service_account_token: Optional[str] = None
    feature_flags: FeatureFlagsConfig = field(default_factory=FeatureFlagsConfig)
    # ... other configs
```

### 2. Security Hardening (`security_hardening.py`)

**Purpose**: Advanced security controls and memory protection

**Key Features**:
- **SecureString**: Memory protection for sensitive data
- **Request Signing**: HMAC-based request integrity
- **TLS Enforcement**: Secure transport configuration
- **Environment Validation**: Security posture assessment

**Design Patterns**:
- **Context Managers**: Automatic resource cleanup
- **Cryptographic Primitives**: Industry-standard algorithms
- **Defense in Depth**: Multiple security layers

```python
class SecureString:
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self._secure_clear()  # Automatic memory cleanup
```

### 3. Resilience Patterns (`resilience.py`)

**Purpose**: Fault tolerance and reliability

**Key Components**:
- **Circuit Breaker**: Prevents cascading failures
- **Retry Logic**: Exponential backoff with jitter
- **Timeout Management**: Configurable request timeouts
- **Error Classification**: Retryable vs non-retryable errors

**Design Patterns**:
- **State Machine**: Circuit breaker state management
- **Decorator Pattern**: Transparent resilience wrapping
- **Strategy Pattern**: Pluggable retry strategies

```python
class CircuitBreaker:
    def __init__(self, failure_threshold: int, recovery_timeout: int):
        self.state = CircuitBreakerState.CLOSED
        self.failure_count = 0
        # State machine implementation
```

### 4. Structured Logging (`structured_logging.py`)

**Purpose**: Comprehensive observability and audit trails

**Key Features**:
- **JSON Logging**: Machine-readable log format
- **Correlation IDs**: Request tracing across components
- **PII Scrubbing**: Automatic credential data protection
- **Performance Timing**: Request duration tracking

**Design Patterns**:
- **Context Propagation**: Correlation ID threading
- **Aspect-Oriented Logging**: Transparent performance measurement
- **Event-Driven Architecture**: Structured event emission

```python
with CorrelationContext(correlation_id):
    with PerformanceTimer(logger, "operation"):
        # Operation execution with automatic timing
        result = await operation()
```

### 5. Monitoring System (`monitoring.py`)

**Purpose**: Health checks and operational metrics

**Key Components**:
- **Health Checker**: Multi-dimensional health assessment
- **Metrics Collector**: Prometheus-style metrics
- **Operational Dashboard**: Performance insights

**Design Patterns**:
- **Registry Pattern**: Metric registration and lookup
- **Observer Pattern**: Health check subscriptions
- **Factory Pattern**: Health check creation

### 6. MCP Protocol Compliance (`mcp_protocol_compliance.py`)

**Purpose**: Full Model Context Protocol support

**Key Features**:
- **Tool Discovery**: Enhanced metadata exposure
- **Resource Management**: Vault and credential resources
- **Transport Abstraction**: Multiple transport support
- **Capability Negotiation**: Version compatibility

## Development Setup

### Prerequisites

```bash
# Install Python 3.12+
pyenv install 3.12.0
pyenv local 3.12.0

# Install uv package manager
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install development dependencies
uv sync --extra dev
```

### Environment Setup

```bash
# Copy environment template
cp .env.example .env

# Set development token
export OP_SERVICE_ACCOUNT_TOKEN=ops_dev_token_here

# Enable development features
export ENVIRONMENT=development
export LOG_LEVEL=DEBUG
export ENABLE_DEBUG_ENDPOINTS=true  # Development only
```

### IDE Configuration

**VS Code Settings** (`.vscode/settings.json`):
```json
{
  "python.defaultInterpreter": ".venv/bin/python",
  "python.linting.enabled": true,
  "python.linting.mypyEnabled": true,
  "python.formatting.provider": "black",
  "python.testing.pytestEnabled": true
}
```

**PyCharm Configuration**:
- Python Interpreter: Project venv
- Code Style: Black formatter
- Test Runner: pytest
- Type Checker: mypy

## Code Structure

### Project Layout

```
onepassword_mcp_server/
├── __init__.py              # Package initialization
├── server.py                # Main server and MCP tools
├── config.py                # Configuration management
├── security_hardening.py    # Security controls
├── resilience.py            # Fault tolerance patterns
├── structured_logging.py    # Logging and observability
├── monitoring.py            # Health checks and metrics
├── mcp_protocol_compliance.py # MCP protocol support
├── test_unit.py             # Unit test suite
└── test_p1_features.py      # P1 feature integration tests

docs/
├── SETUP_GUIDE.md          # Installation and setup
├── SECURITY_GUIDE.md       # Security best practices
├── TROUBLESHOOTING.md      # Common issues and solutions
├── API_REFERENCE.md        # Tool documentation
└── DEVELOPER_GUIDE.md      # This file

tests/                       # Additional test files (future)
```

### Module Dependencies

```
server.py
├── config.py (configuration)
├── security_hardening.py (security controls)
├── resilience.py (fault tolerance)
├── structured_logging.py (observability)
├── monitoring.py (health checks)
└── mcp_protocol_compliance.py (MCP support)

config.py
└── [standard library only]

security_hardening.py
└── cryptography (external)

resilience.py
└── [standard library only]

structured_logging.py
└── [standard library only]

monitoring.py
├── structured_logging.py
└── [standard library only]

mcp_protocol_compliance.py
└── mcp (external)
```

### Code Conventions

#### Naming Conventions

- **Classes**: PascalCase (`OnePasswordSecureClient`)
- **Functions**: snake_case (`get_credentials`)
- **Constants**: UPPER_SNAKE_CASE (`DEFAULT_TIMEOUT`)
- **Private Methods**: Leading underscore (`_authenticate`)

#### Documentation Standards

```python
def get_credentials(self, request: CredentialRequest) -> Dict[str, str]:
    """
    Securely retrieve credentials with comprehensive error handling.
    
    Args:
        request: Validated credential request with item name and vault
        
    Returns:
        Dictionary containing username, password, and metadata
        
    Raises:
        ValidationError: Invalid input parameters
        AuthenticationError: 1Password authentication failed
        RateLimitError: Rate limit exceeded
        CircuitBreakerOpenError: Service protection active
        
    Example:
        >>> request = CredentialRequest(item_name="github.com")
        >>> credentials = await client.get_credentials(request)
        >>> print(credentials["username"])
    """
```

#### Error Handling Patterns

```python
# Use specific exception types
try:
    result = await operation()
except OnePasswordError as e:
    # Handle 1Password-specific errors
    logger.error("1Password error", error_message=str(e))
    raise AuthenticationError(f"Authentication failed: {e}")
except Exception as e:
    # Handle unexpected errors
    logger.error("Unexpected error", error_type=type(e).__name__)
    raise
```

#### Async/Await Patterns

```python
# Use async context managers for resource management
async with client_session() as session:
    result = await session.request(url)

# Prefer async comprehensions where appropriate
results = [await process(item) async for item in async_generator()]

# Use asyncio.gather for concurrent operations
health_checks = await asyncio.gather(
    basic_health_check(),
    onepassword_connectivity_check(),
    return_exceptions=True
)
```

## Contributing Guidelines

### Development Workflow

1. **Fork and Clone**:
   ```bash
   git clone https://github.com/your-fork/1password-mcp-server.git
   cd 1password-mcp-server
   ```

2. **Create Feature Branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Development**:
   ```bash
   # Install dependencies
   uv sync --extra dev
   
   # Make changes
   # Write tests
   # Update documentation
   ```

4. **Quality Checks**:
   ```bash
   # Run tests
   pytest

   # Type checking
   mypy onepassword_mcp_server/
   
   # Code formatting
   black onepassword_mcp_server/
   
   # Linting
   ruff onepassword_mcp_server/
   ```

5. **Submit Pull Request**:
   - Clear description of changes
   - Include test coverage
   - Update documentation
   - Follow security guidelines

### Code Review Process

**Review Criteria**:
- [ ] Security implications assessed
- [ ] Test coverage ≥ 80% for new code
- [ ] Documentation updated
- [ ] Error handling comprehensive
- [ ] Performance impact evaluated
- [ ] Breaking changes documented

**Security Review Required For**:
- Authentication/authorization changes
- Input validation modifications
- Cryptographic operations
- Configuration changes affecting security
- New external dependencies

### Commit Guidelines

**Commit Message Format**:
```
type(scope): short description

Longer description if needed

- Bullet points for details
- Reference issues: Fixes #123
```

**Commit Types**:
- `feat`: New features
- `fix`: Bug fixes
- `security`: Security improvements
- `perf`: Performance improvements
- `docs`: Documentation updates
- `test`: Test additions/improvements
- `refactor`: Code restructuring

## Testing

### Test Structure

```
tests/
├── unit/
│   ├── test_config.py           # Configuration testing
│   ├── test_security.py         # Security controls testing
│   ├── test_resilience.py       # Fault tolerance testing
│   └── test_monitoring.py       # Health checks testing
├── integration/
│   ├── test_onepassword.py      # 1Password SDK integration
│   ├── test_mcp_protocol.py     # MCP protocol compliance
│   └── test_end_to_end.py       # Complete workflow testing
└── performance/
    └── test_load.py             # Performance and load testing
```

### Test Categories

#### Unit Tests

```python
class TestConfigurationManagement:
    def test_feature_flags_defaults(self):
        """Test secure defaults for feature flags"""
        flags = FeatureFlagsConfig()
        assert flags.enable_write_operations is False
    
    @patch.dict(os.environ, {'OP_SERVICE_ACCOUNT_TOKEN': 'ops_test_token'})
    def test_environment_loading(self):
        """Test configuration loading from environment"""
        config = ConfigLoader.load_from_environment()
        assert config.service_account_token == 'ops_test_token'
```

#### Integration Tests

```python
class TestOnePasswordIntegration:
    @pytest.mark.asyncio
    async def test_authentication_flow(self):
        """Test complete authentication with 1Password"""
        # Requires test service account
        config = create_test_config()
        client = OnePasswordSecureClient(config, metrics)
        
        result = await client._authenticate()
        assert result is not None
```

#### Performance Tests

```python
class TestPerformance:
    @pytest.mark.asyncio
    async def test_credential_retrieval_performance(self):
        """Test credential retrieval meets performance SLA"""
        start_time = time.perf_counter()
        
        result = await get_1password_credentials("test-item")
        
        duration = time.perf_counter() - start_time
        assert duration < 5.0  # 5 second SLA
```

### Running Tests

```bash
# All tests
pytest

# Unit tests only
pytest tests/unit/

# With coverage
pytest --cov=onepassword_mcp_server --cov-report=html

# Performance tests
pytest tests/performance/ -v

# Integration tests (requires 1Password setup)
OP_SERVICE_ACCOUNT_TOKEN=ops_test_token pytest tests/integration/
```

### Mock Strategies

```python
# Mock external dependencies
@patch('onepassword_mcp_server.server.Client.authenticate')
async def test_authentication_failure(mock_auth):
    mock_auth.side_effect = OnePasswordError("Invalid token")
    
    with pytest.raises(AuthenticationError):
        await client._authenticate()

# Mock configuration for isolated testing
@patch('onepassword_mcp_server.server.config')
def test_validation_logic(mock_config):
    mock_config.security.max_item_name_length = 10
    
    with pytest.raises(ValueError):
        CredentialRequest(item_name="very_long_name")
```

## Release Process

### Version Management

**Semantic Versioning** (MAJOR.MINOR.PATCH):
- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

**Version Sources**:
- `pyproject.toml`: Package version
- Git tags: Release tracking
- `__init__.py`: Runtime version

### Release Checklist

1. **Pre-Release**:
   - [ ] All tests passing
   - [ ] Documentation updated
   - [ ] Security review completed
   - [ ] Performance benchmarks within SLA
   - [ ] Breaking changes documented

2. **Security Validation**:
   - [ ] Static analysis (bandit, safety)
   - [ ] Dependency vulnerability scan
   - [ ] Configuration security review
   - [ ] Credential handling verification

3. **Build and Package**:
   ```bash
   # Update version in pyproject.toml
   # Create release notes
   
   # Build package
   uv build
   
   # Test package installation
   pip install dist/onepassword_mcp_server-*.whl
   ```

4. **Release**:
   ```bash
   # Create git tag
   git tag -a v1.1.0 -m "Release v1.1.0"
   git push origin v1.1.0
   
   # Upload to PyPI
   uv publish
   ```

5. **Post-Release**:
   - [ ] GitHub release created
   - [ ] Documentation deployed
   - [ ] Security advisory (if applicable)
   - [ ] Community notification

### Hotfix Process

**Critical Security Issues**:
1. Create hotfix branch from latest release
2. Implement minimal fix
3. Emergency security review
4. Fast-track release process
5. Security advisory publication

### Backward Compatibility

**Compatibility Promise**:
- Configuration format stability
- MCP tool interface stability
- Major version for breaking changes
- Deprecation warnings for 1 minor version

**Breaking Change Process**:
1. Deprecation warning in current version
2. Documentation of migration path
3. Breaking change in next major version
4. Migration guide publication

---

For additional development information:
- [Setup Guide](SETUP_GUIDE.md) - Development environment setup
- [Security Guide](SECURITY_GUIDE.md) - Security development practices
- [API Reference](API_REFERENCE.md) - Tool interface specifications