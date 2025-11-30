#!/usr/bin/env python3
"""
P1 MCP Protocol Compliance for 1Password MCP Server

This module implements full MCP protocol compliance including:
- Tool discovery with comprehensive metadata
- Resource exposure capabilities
- Prompt templates for common patterns
- Multiple transport support (stdio, SSE, HTTP)
- Backwards compatibility with older MCP versions
"""

import json
import asyncio
import uuid
from typing import Dict, Any, List, Optional, Union, Callable, AsyncGenerator, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime
from abc import ABC, abstractmethod
import inspect
from functools import wraps

from mcp.server.fastmcp import FastMCP
from mcp.types import Tool, Prompt, Resource
# The MCP SDK renamed ToolResult to CallToolResult in recent versions.
# We alias it as ToolResult for backwards compatibility with existing code.
from mcp.types import CallToolResult as ToolResult, PromptMessage, JSONRPCMessage


class TransportType(Enum):
    """Supported MCP transport types"""
    STDIO = "stdio"
    SSE = "sse"
    HTTP = "http"
    WEBSOCKET = "websocket"


class MCPVersion(Enum):
    """Supported MCP protocol versions"""
    V1_0 = "1.0"
    V1_1 = "1.1"
    V1_6 = "1.6"
    LATEST = "1.6"


@dataclass
class ToolMetadata:
    """Enhanced tool metadata for discovery"""
    name: str
    description: str
    parameters: Dict[str, Any]
    
    # Enhanced metadata
    category: str = "general"
    tags: List[str] = field(default_factory=list)
    version: str = "1.0.0"
    author: str = "1Password MCP Server"
    requires_auth: bool = True
    rate_limited: bool = True
    experimental: bool = False
    deprecated: bool = False
    examples: List[Dict[str, Any]] = field(default_factory=list)
    related_tools: List[str] = field(default_factory=list)
    
    # Performance characteristics
    typical_response_time_ms: int = 1000
    max_response_time_ms: int = 30000
    memory_usage_mb: int = 10
    
    # Security metadata
    security_level: str = "high"  # low, medium, high, critical
    audit_required: bool = True
    sensitive_data: bool = True


@dataclass
class ResourceMetadata:
    """Enhanced resource metadata"""
    uri: str
    name: str
    description: str
    mime_type: str = "application/json"
    
    # Enhanced metadata
    category: str = "data"
    size_bytes: Optional[int] = None
    last_modified: Optional[datetime] = None
    version: str = "1.0.0"
    access_level: str = "authenticated"  # public, authenticated, admin
    cacheable: bool = False
    compression: str = "none"  # none, gzip, deflate
    
    # Dependencies
    depends_on: List[str] = field(default_factory=list)
    provides: List[str] = field(default_factory=list)


@dataclass
class PromptTemplate:
    """Enhanced prompt template"""
    name: str
    description: str
    parameters: Dict[str, Any]
    template: str
    
    # Enhanced metadata
    category: str = "general"
    use_case: str = ""
    complexity: str = "simple"  # simple, medium, complex
    language: str = "en"
    version: str = "1.0.0"
    examples: List[Dict[str, Any]] = field(default_factory=list)
    related_tools: List[str] = field(default_factory=list)


class MCPTransport(ABC):
    """Abstract base class for MCP transports"""
    
    @abstractmethod
    async def send_message(self, message: JSONRPCMessage) -> None:
        """Send a message via this transport"""
        pass
    
    @abstractmethod
    async def receive_message(self) -> JSONRPCMessage:
        """Receive a message via this transport"""
        pass
    
    @abstractmethod
    async def close(self) -> None:
        """Close the transport"""
        pass


class StdioTransport(MCPTransport):
    """Standard I/O transport for MCP"""
    
    def __init__(self):
        self.reader = None
        self.writer = None
    
    async def initialize(self):
        """Initialize the stdio transport"""
        import sys
        self.reader = asyncio.StreamReader()
        self.writer = asyncio.StreamWriter(sys.stdout, None, None, None)
    
    async def send_message(self, message: JSONRPCMessage) -> None:
        """Send message to stdout"""
        if not self.writer:
            await self.initialize()
        
        json_str = json.dumps(asdict(message))
        self.writer.write(f"{json_str}\n".encode())
        await self.writer.drain()
    
    async def receive_message(self) -> JSONRPCMessage:
        """Receive message from stdin"""
        if not self.reader:
            await self.initialize()
        
        line = await self.reader.readline()
        data = json.loads(line.decode().strip())
        return JSONRPCMessage(**data)
    
    async def close(self) -> None:
        """Close the transport"""
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()


class MCPProtocolManager:
    """Manages MCP protocol compliance and features"""
    
    def __init__(self, server_name: str = "1Password MCP Server", version: str = "1.1.0"):
        self.server_name = server_name
        self.version = version
        self.supported_versions = [MCPVersion.V1_0, MCPVersion.V1_1, MCPVersion.V1_6]
        self.supported_transports = [TransportType.STDIO, TransportType.HTTP]
        
        # Protocol features
        self.tools: Dict[str, ToolMetadata] = {}
        self.resources: Dict[str, ResourceMetadata] = {}
        self.prompts: Dict[str, PromptTemplate] = {}
        self.transports: Dict[TransportType, MCPTransport] = {}
        
        # Capabilities
        self.capabilities = {
            "experimental": {},
            "sampling": {},
            "tools": {"listChanged": True},
            "prompts": {"listChanged": True},
            "resources": {"subscribe": True, "listChanged": True}
        }
        
        # Initialize built-in prompt templates
        self._initialize_prompt_templates()
    
    def _initialize_prompt_templates(self):
        """Initialize built-in prompt templates"""
        
        # Credential retrieval template
        self.prompts["get_credentials"] = PromptTemplate(
            name="get_credentials",
            description="Template for retrieving 1Password credentials securely",
            parameters={
                "item_name": {
                    "type": "string",
                    "description": "Name of the 1Password item to retrieve",
                    "required": True
                },
                "vault": {
                    "type": "string", 
                    "description": "Name of the 1Password vault (optional)",
                    "required": False
                },
                "purpose": {
                    "type": "string",
                    "description": "Purpose for credential access (for audit)",
                    "required": False
                }
            },
            template="""I need to retrieve credentials for the following item:
- Item Name: {item_name}
- Vault: {vault or 'default vault'}
- Purpose: {purpose or 'general access'}

Please retrieve the username and password for this item securely.""",
            category="security",
            use_case="Secure credential retrieval for automated systems",
            complexity="simple",
            examples=[
                {
                    "parameters": {
                        "item_name": "database-prod",
                        "vault": "Infrastructure",
                        "purpose": "Database connection for backup script"
                    },
                    "expected_usage": "Retrieving production database credentials"
                }
            ],
            related_tools=["get_1password_credentials"]
        )
        
        # Health check template
        self.prompts["health_check"] = PromptTemplate(
            name="health_check",
            description="Template for checking system health and status",
            parameters={
                "include_metrics": {
                    "type": "boolean",
                    "description": "Include detailed metrics in health check",
                    "required": False
                },
                "check_connectivity": {
                    "type": "boolean", 
                    "description": "Test 1Password connectivity",
                    "required": False
                }
            },
            template="""Please perform a health check of the 1Password MCP server:
- Include metrics: {include_metrics or 'false'}
- Check connectivity: {check_connectivity or 'true'}

Report on server status, connection health, and any issues.""",
            category="monitoring",
            use_case="System health monitoring and diagnostics",
            complexity="simple",
            examples=[
                {
                    "parameters": {
                        "include_metrics": True,
                        "check_connectivity": True
                    },
                    "expected_usage": "Comprehensive health check with metrics"
                }
            ],
            related_tools=["get_health_status", "get_metrics"]
        )
        
        # Troubleshooting template
        self.prompts["troubleshoot"] = PromptTemplate(
            name="troubleshoot",
            description="Template for troubleshooting 1Password MCP server issues",
            parameters={
                "error_description": {
                    "type": "string",
                    "description": "Description of the error or issue",
                    "required": True
                },
                "reproduction_steps": {
                    "type": "string",
                    "description": "Steps to reproduce the issue",
                    "required": False
                },
                "include_logs": {
                    "type": "boolean",
                    "description": "Include recent log entries",
                    "required": False
                }
            },
            template="""I'm experiencing an issue with the 1Password MCP server:

Error: {error_description}

{reproduction_steps and 'Reproduction steps: ' + reproduction_steps or ''}

Please help diagnose the issue{include_logs and ', including relevant log entries' or ''}.""",
            category="support",
            use_case="Troubleshooting and error diagnosis",
            complexity="medium",
            examples=[
                {
                    "parameters": {
                        "error_description": "Authentication failed when retrieving credentials",
                        "reproduction_steps": "1. Call get_1password_credentials\n2. Receive authentication error",
                        "include_logs": True
                    },
                    "expected_usage": "Debugging authentication issues"
                }
            ],
            related_tools=["get_health_status", "get_metrics"]
        )
    
    def register_tool(self, tool_metadata: ToolMetadata, handler: Callable):
        """Register a tool with enhanced metadata"""
        self.tools[tool_metadata.name] = tool_metadata
        
        # Auto-generate examples if not provided
        if not tool_metadata.examples:
            tool_metadata.examples = self._generate_tool_examples(tool_metadata, handler)
    
    def register_resource(self, resource_metadata: ResourceMetadata, provider: Callable):
        """Register a resource with enhanced metadata"""
        self.resources[resource_metadata.uri] = resource_metadata
    
    def register_prompt_template(self, prompt_template: PromptTemplate):
        """Register a prompt template"""
        self.prompts[prompt_template.name] = prompt_template
    
    def _generate_tool_examples(self, tool_metadata: ToolMetadata, handler: Callable) -> List[Dict[str, Any]]:
        """Auto-generate examples for a tool based on its parameters"""
        examples = []
        
        # Generate basic example
        if tool_metadata.name == "get_1password_credentials":
            examples.append({
                "parameters": {
                    "item_name": "example-service",
                    "vault": "Development"
                },
                "description": "Retrieve credentials for a development service",
                "expected_result": "Returns username and password for the specified item"
            })
        
        elif tool_metadata.name == "get_health_status":
            examples.append({
                "parameters": {},
                "description": "Check server health status",
                "expected_result": "Returns comprehensive health information"
            })
        
        elif tool_metadata.name == "get_metrics":
            examples.append({
                "parameters": {},
                "description": "Get operational metrics",
                "expected_result": "Returns performance and operational metrics"
            })
        
        return examples
    
    def get_server_info(self) -> Dict[str, Any]:
        """Get server information for MCP handshake"""
        return {
            "name": self.server_name,
            "version": self.version,
            "protocol_version": MCPVersion.LATEST.value,
            "supported_versions": [v.value for v in self.supported_versions],
            "supported_transports": [t.value for t in self.supported_transports],
            "capabilities": self.capabilities,
            "description": "Secure 1Password credential retrieval with comprehensive error handling, resilience patterns, and monitoring",
            "author": "1Password MCP Server Contributors",
            "license": "MIT",
            "homepage": "https://github.com/1password/mcp-server",
            "features": [
                "secure_credential_retrieval",
                "circuit_breaker_pattern",
                "comprehensive_logging",
                "health_monitoring",
                "rate_limiting",
                "memory_protection",
                "transport_security",
                "request_signing"
            ]
        }
    
    def list_tools(self, category: str = None) -> List[Dict[str, Any]]:
        """List available tools with metadata"""
        tools = []
        
        for tool_name, tool_metadata in self.tools.items():
            if category and tool_metadata.category != category:
                continue
            
            tool_dict = asdict(tool_metadata)
            
            # Add runtime metadata
            tool_dict["available"] = True
            tool_dict["last_used"] = None
            tool_dict["usage_count"] = 0
            
            tools.append(tool_dict)
        
        return tools
    
    def list_resources(self, category: str = None) -> List[Dict[str, Any]]:
        """List available resources with metadata"""
        resources = []
        
        for uri, resource_metadata in self.resources.items():
            if category and resource_metadata.category != category:
                continue
            
            resource_dict = asdict(resource_metadata)
            
            # Add runtime metadata
            resource_dict["available"] = True
            resource_dict["last_accessed"] = None
            resource_dict["access_count"] = 0
            
            resources.append(resource_dict)
        
        return resources
    
    def list_prompts(self, category: str = None) -> List[Dict[str, Any]]:
        """List available prompt templates with metadata"""
        prompts = []
        
        for prompt_name, prompt_template in self.prompts.items():
            if category and prompt_template.category != category:
                continue
            
            prompt_dict = asdict(prompt_template)
            
            # Add runtime metadata
            prompt_dict["available"] = True
            prompt_dict["usage_count"] = 0
            
            prompts.append(prompt_dict)
        
        return prompts
    
    def get_tool_schema(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Get JSON schema for a specific tool"""
        if tool_name not in self.tools:
            return None
        
        tool_metadata = self.tools[tool_name]
        
        return {
            "type": "object",
            "properties": tool_metadata.parameters,
            "required": [
                param_name for param_name, param_def in tool_metadata.parameters.items()
                if param_def.get("required", False)
            ],
            "additionalProperties": False,
            "title": tool_metadata.name,
            "description": tool_metadata.description,
            "examples": tool_metadata.examples
        }
    
    def render_prompt_template(self, template_name: str, parameters: Dict[str, Any]) -> str:
        """Render a prompt template with given parameters"""
        if template_name not in self.prompts:
            raise ValueError(f"Unknown prompt template: {template_name}")
        
        template = self.prompts[template_name]
        
        try:
            return template.template.format(**parameters)
        except KeyError as e:
            raise ValueError(f"Missing required parameter for template '{template_name}': {e}")
    
    def validate_tool_parameters(self, tool_name: str, parameters: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate parameters for a tool"""
        if tool_name not in self.tools:
            return False, [f"Unknown tool: {tool_name}"]
        
        tool_metadata = self.tools[tool_name]
        errors = []
        
        # Check required parameters
        for param_name, param_def in tool_metadata.parameters.items():
            if param_def.get("required", False) and param_name not in parameters:
                errors.append(f"Missing required parameter: {param_name}")
        
        # Check parameter types (basic validation)
        for param_name, param_value in parameters.items():
            if param_name in tool_metadata.parameters:
                param_def = tool_metadata.parameters[param_name]
                expected_type = param_def.get("type")
                
                if expected_type == "string" and not isinstance(param_value, str):
                    errors.append(f"Parameter '{param_name}' must be a string")
                elif expected_type == "integer" and not isinstance(param_value, int):
                    errors.append(f"Parameter '{param_name}' must be an integer")
                elif expected_type == "boolean" and not isinstance(param_value, bool):
                    errors.append(f"Parameter '{param_name}' must be a boolean")
        
        return len(errors) == 0, errors
    
    def get_capabilities(self) -> Dict[str, Any]:
        """Get server capabilities"""
        return {
            **self.capabilities,
            "tools": {
                **self.capabilities.get("tools", {}),
                "available_tools": len(self.tools),
                "categories": list(set(tool.category for tool in self.tools.values()))
            },
            "prompts": {
                **self.capabilities.get("prompts", {}), 
                "available_prompts": len(self.prompts),
                "categories": list(set(prompt.category for prompt in self.prompts.values()))
            },
            "resources": {
                **self.capabilities.get("resources", {}),
                "available_resources": len(self.resources),
                "categories": list(set(resource.category for resource in self.resources.values()))
            }
        }
    
    def add_transport(self, transport_type: TransportType, transport: MCPTransport):
        """Add a transport for multi-transport support"""
        self.transports[transport_type] = transport
        if transport_type not in self.supported_transports:
            self.supported_transports.append(transport_type)
    
    async def handle_protocol_negotiation(self, client_version: str) -> Dict[str, Any]:
        """Handle MCP protocol version negotiation"""
        
        # Find best compatible version
        compatible_version = None
        client_versions = [client_version] if isinstance(client_version, str) else client_version
        
        for version_str in client_versions:
            try:
                version = MCPVersion(version_str)
                if version in self.supported_versions:
                    compatible_version = version
                    break
            except ValueError:
                continue
        
        if not compatible_version:
            # Fall back to earliest supported version
            compatible_version = min(self.supported_versions, key=lambda v: v.value)
        
        return {
            "protocol_version": compatible_version.value,
            "server_info": self.get_server_info(),
            "capabilities": self.get_capabilities()
        }


def create_enhanced_mcp_server(protocol_manager: MCPProtocolManager, stateless_http: bool = False) -> FastMCP:
    """Create an enhanced MCP server with full protocol compliance
    
    Args:
        protocol_manager: The MCP protocol manager instance
        stateless_http: If True, enables stateless HTTP mode for scalable cloud deployments
                       like Smithery. This is required for deployments where each request
                       may be handled by a different server instance.
    """
    
    mcp = FastMCP(protocol_manager.server_name, stateless_http=stateless_http)
    
    # Add protocol compliance endpoints
    
    @mcp.tool()
    async def list_mcp_tools(category: str = None) -> Dict[str, Any]:
        """List all available MCP tools with enhanced metadata"""
        tools = protocol_manager.list_tools(category)
        return {
            "tools": tools,
            "total_count": len(tools),
            "categories": list(set(tool["category"] for tool in tools)),
            "server_info": protocol_manager.get_server_info()
        }
    
    @mcp.tool()
    async def list_mcp_prompts(category: str = None) -> Dict[str, Any]:
        """List all available prompt templates with metadata"""
        prompts = protocol_manager.list_prompts(category)
        return {
            "prompts": prompts,
            "total_count": len(prompts),
            "categories": list(set(prompt["category"] for prompt in prompts)),
            "server_info": protocol_manager.get_server_info()
        }
    
    @mcp.tool()
    async def list_mcp_resources(category: str = None) -> Dict[str, Any]:
        """List all available resources with metadata"""
        resources = protocol_manager.list_resources(category)
        return {
            "resources": resources,
            "total_count": len(resources),
            "categories": list(set(resource["category"] for resource in resources)),
            "server_info": protocol_manager.get_server_info()
        }
    
    @mcp.tool()
    async def get_mcp_capabilities() -> Dict[str, Any]:
        """Get comprehensive MCP server capabilities"""
        return protocol_manager.get_capabilities()
    
    @mcp.tool()
    async def render_mcp_prompt(template_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Render a prompt template with given parameters"""
        try:
            rendered = protocol_manager.render_prompt_template(template_name, parameters)
            return {
                "template_name": template_name,
                "rendered_prompt": rendered,
                "parameters_used": parameters,
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            return {
                "error": str(e),
                "template_name": template_name,
                "available_templates": list(protocol_manager.prompts.keys())
            }
    
    @mcp.tool()
    async def validate_mcp_tool_parameters(tool_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Validate parameters for a specific tool"""
        is_valid, errors = protocol_manager.validate_tool_parameters(tool_name, parameters)
        
        schema = protocol_manager.get_tool_schema(tool_name)
        
        return {
            "tool_name": tool_name,
            "parameters": parameters,
            "is_valid": is_valid,
            "validation_errors": errors,
            "schema": schema
        }
    
    return mcp


# Global protocol manager instance
_protocol_manager: Optional[MCPProtocolManager] = None


def initialize_mcp_protocol(server_name: str = "1Password MCP Server", version: str = "1.1.0") -> MCPProtocolManager:
    """Initialize the global MCP protocol manager"""
    global _protocol_manager
    _protocol_manager = MCPProtocolManager(server_name, version)
    return _protocol_manager


def get_protocol_manager() -> Optional[MCPProtocolManager]:
    """Get the global MCP protocol manager"""
    return _protocol_manager


def register_tool_with_metadata(**metadata_kwargs):
    """Decorator to register a tool with enhanced metadata"""
    def decorator(func):
        if _protocol_manager:
            # Extract function signature for parameters
            sig = inspect.signature(func)
            parameters = {}
            
            for param_name, param in sig.parameters.items():
                param_info = {
                    "type": "string",  # Default type
                    "required": param.default == inspect.Parameter.empty
                }
                
                # Try to infer type from annotation
                if param.annotation != inspect.Parameter.empty:
                    if param.annotation == str:
                        param_info["type"] = "string"
                    elif param.annotation == int:
                        param_info["type"] = "integer"
                    elif param.annotation == bool:
                        param_info["type"] = "boolean"
                    elif param.annotation == dict:
                        param_info["type"] = "object"
                
                parameters[param_name] = param_info
            
            # Create tool metadata
            tool_metadata = ToolMetadata(
                name=func.__name__,
                description=func.__doc__ or f"Tool: {func.__name__}",
                parameters=parameters,
                **metadata_kwargs
            )
            
            _protocol_manager.register_tool(tool_metadata, func)
        
        return func
    
    return decorator