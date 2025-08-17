# 1Password MCP Server - Security Guide

## Table of Contents
- [Security Model](#security-model)
- [Deployment Security](#deployment-security)
- [Configuration Security](#configuration-security)
- [Monitoring and Auditing](#monitoring-and-auditing)
- [Incident Response](#incident-response)
- [Compliance](#compliance)

## Security Model

### Core Security Principles

The 1Password MCP Server follows a **defense-in-depth** security model with multiple layers of protection:

1. **Access Control**: 1Password service account permissions
2. **Network Isolation**: stdio transport only (no network exposure)
3. **Input Validation**: Strict parameter validation and sanitization
4. **Audit Logging**: Complete request/response audit trail
5. **Rate Limiting**: Configurable request throttling
6. **Circuit Protection**: Automatic failure isolation

### Trust Boundaries

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   AI Assistant  │────│  MCP Server      │────│  1Password API  │
│   (Claude)      │    │  (This Service)  │    │  (Remote)       │
└─────────────────┘    └──────────────────┘    └─────────────────┘
      Untrusted              Trusted              External
```

**Security Controls**:
- **Input Sanitization**: All AI requests validated before processing
- **Authentication**: Service account tokens for 1Password API access
- **Authorization**: Vault-level access control
- **Encryption**: TLS for all external communications

### Threat Model

**Mitigated Threats**:
- ✅ **Credential Injection**: Input validation prevents malicious parameters
- ✅ **Privilege Escalation**: Service account scope limits access
- ✅ **Denial of Service**: Rate limiting and circuit breakers
- ✅ **Data Exfiltration**: Audit logging tracks all access
- ✅ **Man-in-the-Middle**: TLS encryption for API calls

**Residual Risks**:
- ⚠️ **AI Model Compromise**: AI assistant could request any accessible credential
- ⚠️ **Service Account Compromise**: Full vault access if token is compromised
- ⚠️ **Local System Access**: Server process has access to environment variables

## Deployment Security

### Production Environment Setup

#### 1. Service Account Configuration

**Create Dedicated Service Account**:
```bash
# Use descriptive naming convention
Service Account Name: "MCP-Server-Production-ReadOnly"
Description: "1Password MCP Server for AI assistant credential access"
```

**Principle of Least Privilege**:
- Grant access to **specific vaults only**
- Use **Read-only permissions** unless write operations required
- Create separate accounts for different environments

**Token Management**:
```bash
# Secure token storage
export OP_SERVICE_ACCOUNT_TOKEN=ops_secure_production_token

# Rotate tokens regularly (recommended: 90 days)
# Document rotation in change management system
```

#### 2. Environment Isolation

**Development Environment**:
```bash
# Separate vault for development
SECURITY_DEFAULT_VAULT=AI-Development
ENVIRONMENT=development
LOG_LEVEL=DEBUG
```

**Staging Environment**:
```bash
# Mirror production configuration
SECURITY_DEFAULT_VAULT=AI-Staging  
ENVIRONMENT=staging
LOG_LEVEL=INFO
```

**Production Environment**:
```bash
# Minimal logging, strict controls
SECURITY_DEFAULT_VAULT=AI-Production
ENVIRONMENT=production
LOG_LEVEL=WARNING
RATE_LIMIT_MAX_REQUESTS=5
```

#### 3. Network Security

**Recommended Network Configuration**:
- **No Network Exposure**: Use stdio transport only
- **Firewall Rules**: Block all inbound connections to server host
- **VPN Access**: Require VPN for administrative access
- **Monitoring**: Network monitoring for unusual traffic patterns

#### 4. Host Security

**Operating System Hardening**:
```bash
# Run as dedicated user
sudo useradd -r -s /bin/false onepassword-mcp
sudo usermod -L onepassword-mcp  # Lock password

# Minimal file permissions
chmod 600 .env
chown onepassword-mcp:onepassword-mcp .env

# Process isolation
# Use containers or systemd user services
```

**File System Security**:
```bash
# Secure configuration files
chmod 600 /etc/onepassword-mcp/config.env
chmod 644 /etc/onepassword-mcp/server.conf
chown root:onepassword-mcp /etc/onepassword-mcp/

# Log file permissions
chmod 640 /var/log/onepassword-mcp/
chown onepassword-mcp:adm /var/log/onepassword-mcp/
```

## Configuration Security

### Secure Configuration Management

#### 1. Environment Variables

**Required Security Settings**:
```bash
# Strong rate limiting
RATE_LIMIT_MAX_REQUESTS=5
RATE_LIMIT_WINDOW_SECONDS=60

# Comprehensive audit logging
LOG_AUDIT_ENABLED=true
LOG_SCRUBBING_ENABLED=true
LOG_LEVEL=WARNING  # Production

# Security hardening
CIRCUIT_BREAKER_FAILURE_THRESHOLD=3
RETRY_MAX_ATTEMPTS=2
MONITORING_HEALTH_CHECK_ENABLED=true
```

**Feature Flag Security**:
```bash
# Destructive operations (default: disabled)
ENABLE_WRITE_OPERATIONS=false  # Only enable with strong justification
```

#### 2. Input Validation Configuration

**Strict Item Name Validation**:
```bash
# Conservative pattern matching
SECURITY_ALLOWED_ITEM_NAME_PATTERN="^[a-zA-Z0-9._-]+$"
SECURITY_MAX_ITEM_NAME_LENGTH=64

# Restrict vault access
SECURITY_DEFAULT_VAULT=AI-Production
```

#### 3. Monitoring Configuration

**Security Monitoring**:
```bash
# Health checks for security monitoring
MONITORING_HEALTH_CHECK_ENABLED=true
MONITORING_HEALTH_CHECK_TIMEOUT=30.0

# Metrics for security analysis
MONITORING_METRICS_ENABLED=true
MONITORING_DASHBOARD_ENABLED=true
```

### Configuration Validation

**Security Configuration Checklist**:
- [ ] Service account token length ≥ 50 characters
- [ ] Environment set to "production"
- [ ] Rate limiting enabled with low thresholds
- [ ] Debug logging disabled in production
- [ ] Audit logging enabled
- [ ] Write operations disabled (unless required)
- [ ] Health monitoring enabled

## Monitoring and Auditing

### Security Event Monitoring

#### 1. Audit Log Analysis

**Critical Events to Monitor**:
```json
{
  "event_type": "audit",
  "operation": "get_credentials",
  "item_name": "production-database",
  "vault": "AI-Production",
  "correlation_id": "req-12345",
  "timestamp": "2024-01-15T10:30:00.000Z",
  "duration_ms": 145.2
}
```

**Security Events**:
```json
{
  "event_type": "security",
  "message": "Rate limit exceeded",
  "operation": "rate_limit_check",
  "client_id": "default",
  "current_count": 10,
  "timestamp": "2024-01-15T10:30:00.000Z"
}
```

#### 2. Alerting Configuration

**High Priority Alerts**:
- **Authentication Failures**: > 5 failures in 5 minutes
- **Rate Limit Violations**: > 10 violations in 1 hour  
- **Circuit Breaker Open**: Any circuit breaker opening
- **Unusual Access Patterns**: Access to new vaults or items

**Log Analysis Queries**:
```bash
# Failed authentication attempts
jq 'select(.event_type=="security" and .message=="Authentication failed")' audit.log

# Rate limit violations
jq 'select(.event_type=="security" and .message=="Rate limit exceeded")' audit.log

# Credential access by item
jq 'select(.operation=="get_credentials") | .item_name' audit.log | sort | uniq -c
```

#### 3. Performance Monitoring

**Security-Relevant Metrics**:
- **Request Rate**: Monitor for DDoS or abuse
- **Error Rate**: High error rates may indicate attacks
- **Response Time**: Performance degradation can indicate resource exhaustion
- **Circuit Breaker State**: Monitor service health

### Log Management

#### 1. Log Retention

**Recommended Retention**:
- **Audit Logs**: 365 days minimum
- **Security Logs**: 180 days minimum  
- **Performance Logs**: 90 days
- **Debug Logs**: 30 days (development only)

#### 2. Log Protection

**Security Controls**:
```bash
# Immutable logs (append-only)
chattr +a /var/log/onepassword-mcp/audit.log

# Log rotation with integrity protection
logrotate -f /etc/logrotate.d/onepassword-mcp

# Centralized log shipping
rsyslog -f /etc/rsyslog.d/onepassword-mcp.conf
```

## Incident Response

### Security Incident Procedures

#### 1. Credential Compromise Response

**Immediate Actions** (< 1 hour):
1. **Revoke Service Account**: Disable compromised token in 1Password
2. **Stop Service**: Immediately stop MCP server instances
3. **Isolate System**: Disconnect from network if necessary
4. **Preserve Evidence**: Copy logs before any changes

**Investigation** (1-4 hours):
1. **Analyze Audit Logs**: Review all credential access in past 24 hours
2. **Check Access Patterns**: Identify unusual or suspicious requests
3. **Verify System Integrity**: Check for unauthorized modifications
4. **Document Timeline**: Create incident timeline with evidence

**Recovery** (4-24 hours):
1. **Create New Service Account**: With updated permissions
2. **Update Configuration**: Deploy new tokens and rotate secrets
3. **Verify Security**: Confirm no persistent compromise
4. **Resume Operations**: Gradually restore service

#### 2. System Compromise Response

**Detection Indicators**:
- Unusual process behavior or resource usage
- Unexpected network connections
- Modified configuration files
- Anomalous log entries

**Response Procedures**:
1. **Immediate Isolation**: Disconnect from network
2. **Evidence Preservation**: Create system image
3. **Malware Analysis**: Scan for malicious code
4. **Configuration Review**: Check for unauthorized changes
5. **Clean Recovery**: Rebuild from known-good state

### Post-Incident Activities

**After Resolution**:
1. **Root Cause Analysis**: Identify security gaps
2. **Process Improvement**: Update procedures and controls
3. **Training**: Educate team on lessons learned
4. **Monitoring Enhancement**: Add new detection rules

## Compliance

### Security Standards Alignment

#### SOC 2 Type II Compliance

**Common Criteria (CC) Mapping**:
- **CC1.0 Control Environment**: Security governance and organizational controls
- **CC2.0 Communication**: Security policy communication and training
- **CC3.0 Risk Assessment**: Regular security risk assessments
- **CC4.0 Monitoring**: Continuous security monitoring
- **CC5.0 Control Activities**: Technical security controls

**Trust Service Criteria**:
- **Security**: Logical and physical access controls
- **Availability**: System uptime and disaster recovery
- **Processing Integrity**: Data accuracy and completeness
- **Confidentiality**: Data protection and encryption
- **Privacy**: Personal information handling (if applicable)

#### Industry Best Practices

**NIST Cybersecurity Framework**:
- **Identify**: Asset inventory and risk assessment
- **Protect**: Access controls and security awareness
- **Detect**: Security monitoring and anomaly detection
- **Respond**: Incident response and communications
- **Recover**: Recovery planning and improvements

**ISO 27001 Controls**:
- **A.9.1**: Access control policy and procedures
- **A.10.1**: Cryptographic controls for data protection
- **A.12.4**: Logging and monitoring activities
- **A.16.1**: Incident management procedures

### Audit Preparation

**Documentation Requirements**:
- [ ] Security policies and procedures
- [ ] Risk assessment and treatment plans
- [ ] Configuration management records
- [ ] Access control matrices
- [ ] Incident response documentation
- [ ] Security monitoring reports
- [ ] Vulnerability management records

**Evidence Collection**:
- [ ] Audit logs with integrity verification
- [ ] Configuration backups with version control
- [ ] Security assessment reports
- [ ] Penetration testing results
- [ ] Security training records
- [ ] Change management documentation

---

For additional security information, see:
- [Main Security Policy](../SECURITY.md)
- [Setup Guide](SETUP_GUIDE.md)
- [Troubleshooting Guide](TROUBLESHOOTING.md)