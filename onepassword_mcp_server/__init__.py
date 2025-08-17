#!/usr/bin/env python3
"""
1Password MCP Server Package

A secure MCP server that provides authenticated 1Password credential retrieval
with comprehensive error handling, resilience patterns, security hardening,
and full MCP protocol compliance.

Features:
- Secure credential retrieval from 1Password
- Circuit breaker pattern for API resilience
- Comprehensive structured logging and monitoring
- Memory protection for sensitive data
- Transport security enforcement
- Request signing and integrity verification
- Full MCP protocol compliance
- Tool discovery and metadata
- Resource exposure and prompt templates
"""

__version__ = "1.1.0"
__author__ = "1Password MCP Server Contributors"
__license__ = "MIT"
__description__ = "Secure 1Password credential retrieval for AI assistants via MCP protocol"

# Package metadata
__all__ = [
    "__version__",
    "__author__", 
    "__license__",
    "__description__",
    "main",
    "ServerConfig",
    "ConfigLoader",
    "OnePasswordSecureClient",
    "SecurityHardeningManager",
    "MCPProtocolManager",
]

# Import main components for easier access
from .config import ServerConfig, ConfigLoader
from .server import OnePasswordSecureClient
from .security_hardening import SecurityHardeningManager
from .mcp_protocol_compliance import MCPProtocolManager

def main():
    """Main entry point for the CLI."""
    import asyncio
    from .server import main as server_main
    asyncio.run(server_main())

# Version info tuple for programmatic access
VERSION_INFO = tuple(map(int, __version__.split('.')))

def get_version() -> str:
    """Get the package version string."""
    return __version__

def get_version_info() -> tuple:
    """Get the package version as a tuple."""
    return VERSION_INFO

def get_package_info() -> dict:
    """Get comprehensive package information."""
    return {
        "name": "onepassword-mcp-server",
        "version": __version__,
        "version_info": VERSION_INFO,
        "author": __author__,
        "license": __license__,
        "description": __description__,
        "features": [
            "secure_credential_retrieval",
            "circuit_breaker_pattern", 
            "comprehensive_logging",
            "health_monitoring",
            "rate_limiting",
            "memory_protection",
            "transport_security",
            "request_signing",
            "mcp_protocol_compliance",
            "tool_discovery",
            "resource_exposure",
            "prompt_templates"
        ]
    }