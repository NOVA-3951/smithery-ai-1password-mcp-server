# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Security Model

This MCP server is designed to provide secure access to 1Password credentials for AI assistants. The security model is based on:

- **Service Account Authentication**: Uses 1Password service account tokens for authentication
- **Vault-based Access Control**: Restricts access to designated vaults (default: "AI" vault)
- **Input Validation**: Validates all input parameters to prevent injection attacks
- **Rate Limiting**: Implements basic rate limiting to prevent abuse
- **Minimal Attack Surface**: Focused functionality with minimal dependencies

## Security Considerations

### Credential Exposure

This server intentionally returns plaintext credentials to AI assistants. Security comes from:

- Access control at the 1Password service account level
- Network isolation (stdio transport only)
- Input validation and sanitization
- Audit logging of credential requests

### Service Account Token Security

- Store tokens securely using environment variables
- Rotate tokens regularly
- Use principle of least privilege when configuring vault access
- Monitor token usage through 1Password's audit logs

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security vulnerability, please follow these steps:

1. **Do NOT** create a public GitHub issue
2. Email security concerns to: [security@your-domain.com] (replace with actual contact)
3. Include the following information:
   - Description of the vulnerability
   - Steps to reproduce the issue
   - Potential impact assessment
   - Suggested fix (if any)

### Response Timeline

- **Initial Response**: Within 48 hours of report
- **Assessment**: Within 7 days
- **Fix Development**: Within 30 days for critical issues
- **Disclosure**: Coordinated disclosure after fix is available

## Security Best Practices

### Deployment

- Run in isolated environments
- Use dedicated service accounts with minimal permissions
- Enable audit logging in 1Password
- Monitor for unusual access patterns
- Regularly update dependencies

### Access Control

- Limit vault access to necessary items only
- Use descriptive item names without sensitive information
- Regularly audit vault permissions
- Implement network-level access controls

### Monitoring

- Monitor 1Password audit logs for unusual activity
- Track credential request patterns
- Alert on authentication failures
- Log all security-relevant events

## Known Security Limitations

1. **Plaintext Credential Transmission**: Credentials are transmitted in plaintext to AI assistants (by design)
2. **No User Authentication**: Authentication is service-account based, not user-specific
3. **Basic Rate Limiting**: Current rate limiting is simple and may not prevent sophisticated attacks
4. **Limited Audit Trail**: Audit capabilities depend on 1Password's service account logging

## Security Dependencies

This project relies on the security of:

- 1Password service accounts and API
- Python MCP SDK security model
- Operating system environment variable security
- Network transport security (when applicable)

## Compliance

This server is designed to support:

- SOC 2 Type II compliance (through 1Password's compliance)
- GDPR compliance (through proper data handling)
- Industry-standard security practices

For specific compliance requirements, please consult with your security team.
