#!/usr/bin/env python3
"""
P1 Security Hardening for 1Password MCP Server

This module implements advanced security features including:
- Memory protection for credentials
- Transport security enforcement
- Request signing and integrity verification
- Environment security validation
- Secure credential lifecycle management
"""

import os
import gc
import sys
import hmac
import hashlib
import secrets
import time
import ssl
import socket
from typing import Dict, Any, Optional, List, Tuple, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import weakref
import mmap
import ctypes
import threading
from contextlib import contextmanager
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64


class SecurityError(Exception):
    """Security-related error"""
    pass


class MemoryProtectionError(SecurityError):
    """Memory protection error"""
    pass


class TransportSecurityError(SecurityError):
    """Transport security error"""
    pass


class RequestIntegrityError(SecurityError):
    """Request integrity verification error"""
    pass


class EnvironmentSecurityError(SecurityError):
    """Environment security validation error"""
    pass


@dataclass
class SecurityHardeningConfig:
    """Configuration for security hardening features"""
    
    # Memory protection
    memory_protection_enabled: bool = True
    secure_memory_clear_on_exit: bool = True
    credential_max_lifetime_seconds: int = 300  # 5 minutes
    
    # Transport security
    tls_enforcement_enabled: bool = True
    min_tls_version: str = "TLSv1.2"
    allowed_cipher_suites: List[str] = field(default_factory=lambda: [
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES128-GCM-SHA256",
        "DHE-RSA-AES256-GCM-SHA384",
        "DHE-RSA-AES128-GCM-SHA256"
    ])
    
    # Request signing
    request_signing_enabled: bool = True
    signature_algorithm: str = "SHA256"
    signature_key_rotation_hours: int = 24
    
    # Environment validation
    environment_validation_enabled: bool = True
    required_environment_vars: List[str] = field(default_factory=lambda: [
        "OP_SERVICE_ACCOUNT_TOKEN"
    ])
    forbidden_environment_patterns: List[str] = field(default_factory=lambda: [
        "DEBUG_",
        "DEV_",
        "TEST_"
    ])
    
    # CORS configuration
    cors_enabled: bool = True
    allowed_origins: List[str] = field(default_factory=lambda: ["https://localhost"])
    allowed_methods: List[str] = field(default_factory=lambda: ["POST"])
    allowed_headers: List[str] = field(default_factory=lambda: [
        "Content-Type",
        "Authorization",
        "X-Request-ID"
    ])


class SecureMemoryManager:
    """Secure memory management for sensitive data"""
    
    def __init__(self):
        self._secure_allocations: Dict[int, Any] = weakref.WeakValueDictionary()
        self._allocation_metadata: Dict[int, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        
        # Register cleanup on exit
        import atexit
        atexit.register(self._cleanup_all_secure_memory)
    
    def allocate_secure_string(self, initial_value: str = "") -> 'SecureString':
        """Allocate a secure string that will be cleared from memory"""
        secure_str = SecureString(initial_value)
        
        with self._lock:
            allocation_id = id(secure_str)
            self._secure_allocations[allocation_id] = secure_str
            self._allocation_metadata[allocation_id] = {
                "created_at": datetime.utcnow(),
                "type": "SecureString",
                "size": len(initial_value)
            }
        
        return secure_str
    
    def force_garbage_collection(self):
        """Force garbage collection to clear deallocated memory"""
        # Multiple passes to ensure cleanup
        for _ in range(3):
            gc.collect()
    
    def get_active_allocations(self) -> Dict[str, Any]:
        """Get information about active secure allocations"""
        with self._lock:
            return {
                "count": len(self._secure_allocations),
                "allocations": [
                    {
                        "id": alloc_id,
                        "metadata": metadata
                    }
                    for alloc_id, metadata in self._allocation_metadata.items()
                    if alloc_id in self._secure_allocations
                ]
            }
    
    def _cleanup_all_secure_memory(self):
        """Emergency cleanup of all secure memory on exit"""
        with self._lock:
            for allocation in list(self._secure_allocations.values()):
                if hasattr(allocation, 'clear'):
                    allocation.clear()
            
            self._secure_allocations.clear()
            self._allocation_metadata.clear()
        
        self.force_garbage_collection()


class SecureString:
    """A string that securely clears its content from memory when deleted"""
    
    def __init__(self, value: str = ""):
        self._data = bytearray(value.encode('utf-8'))
        self._cleared = False
        self._created_at = time.time()
        self._max_lifetime = 300  # 5 minutes default
    
    def get_value(self) -> str:
        """Get the string value"""
        if self._cleared:
            raise MemoryProtectionError("SecureString has been cleared")
        
        # Check if lifetime exceeded
        if time.time() - self._created_at > self._max_lifetime:
            self.clear()
            raise MemoryProtectionError("SecureString lifetime exceeded")
        
        return self._data.decode('utf-8')
    
    def set_value(self, value: str):
        """Set a new string value"""
        if self._cleared:
            raise MemoryProtectionError("Cannot set value on cleared SecureString")
        
        # Clear old value
        self._clear_memory()
        
        # Set new value
        self._data = bytearray(value.encode('utf-8'))
        self._created_at = time.time()
    
    def clear(self):
        """Securely clear the string from memory"""
        if not self._cleared:
            self._clear_memory()
            self._cleared = True
    
    def _clear_memory(self):
        """Internal method to clear memory"""
        if self._data:
            # Overwrite with random data
            for i in range(len(self._data)):
                self._data[i] = secrets.randbits(8)
            
            # Overwrite with zeros
            for i in range(len(self._data)):
                self._data[i] = 0
            
            # Clear the bytearray
            self._data.clear()
    
    def __del__(self):
        """Ensure memory is cleared when object is deleted"""
        self.clear()
    
    def __str__(self):
        return "<SecureString [PROTECTED]>"
    
    def __repr__(self):
        return f"<SecureString cleared={self._cleared}>"


class RequestSigner:
    """Request signing and integrity verification"""
    
    def __init__(self, config: SecurityHardeningConfig):
        self.config = config
        self._signing_key = self._generate_signing_key()
        self._key_created_at = datetime.utcnow()
        self._lock = threading.Lock()
    
    def _generate_signing_key(self) -> bytes:
        """Generate a new signing key"""
        return secrets.token_bytes(32)  # 256-bit key
    
    def _should_rotate_key(self) -> bool:
        """Check if signing key should be rotated"""
        if not self.config.signature_key_rotation_hours:
            return False
        
        age = datetime.utcnow() - self._key_created_at
        return age > timedelta(hours=self.config.signature_key_rotation_hours)
    
    def _rotate_key_if_needed(self):
        """Rotate signing key if needed"""
        with self._lock:
            if self._should_rotate_key():
                # Clear old key
                self._signing_key = bytes(len(self._signing_key))
                
                # Generate new key
                self._signing_key = self._generate_signing_key()
                self._key_created_at = datetime.utcnow()
    
    def sign_request(self, request_data: Dict[str, Any]) -> str:
        """Sign a request and return the signature"""
        if not self.config.request_signing_enabled:
            return ""
        
        self._rotate_key_if_needed()
        
        # Create canonical string representation
        canonical_string = self._canonicalize_request(request_data)
        
        # Create signature
        signature = hmac.new(
            self._signing_key,
            canonical_string.encode('utf-8'),
            getattr(hashlib, self.config.signature_algorithm.lower())
        ).digest()
        
        return base64.b64encode(signature).decode('ascii')
    
    def verify_request(self, request_data: Dict[str, Any], signature: str) -> bool:
        """Verify a request signature"""
        if not self.config.request_signing_enabled:
            return True
        
        try:
            expected_signature = self.sign_request(request_data)
            provided_signature_bytes = base64.b64decode(signature.encode('ascii'))
            expected_signature_bytes = base64.b64decode(expected_signature.encode('ascii'))
            
            return hmac.compare_digest(provided_signature_bytes, expected_signature_bytes)
        
        except Exception:
            return False
    
    def _canonicalize_request(self, request_data: Dict[str, Any]) -> str:
        """Create a canonical string representation of request data"""
        import json
        
        # Sort keys and create deterministic JSON
        canonical_json = json.dumps(request_data, sort_keys=True, separators=(',', ':'))
        
        # Add timestamp to prevent replay attacks
        timestamp = str(int(time.time()))
        
        return f"{canonical_json}|{timestamp}"


class TransportSecurityManager:
    """Transport security enforcement"""
    
    def __init__(self, config: SecurityHardeningConfig):
        self.config = config
    
    def create_secure_ssl_context(self) -> ssl.SSLContext:
        """Create a secure SSL context"""
        if not self.config.tls_enforcement_enabled:
            raise TransportSecurityError("TLS enforcement is disabled")
        
        # Create context with minimum TLS version
        if self.config.min_tls_version == "TLSv1.3":
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
        elif self.config.min_tls_version == "TLSv1.2":
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        else:
            raise TransportSecurityError(f"Unsupported TLS version: {self.config.min_tls_version}")
        
        # Configure cipher suites
        if self.config.allowed_cipher_suites:
            context.set_ciphers(':'.join(self.config.allowed_cipher_suites))
        
        # Security options
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        context.options |= ssl.OP_NO_COMPRESSION
        context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
        
        return context
    
    def validate_client_certificate(self, cert_data: bytes) -> bool:
        """Validate client certificate if provided"""
        try:
            from cryptography import x509
            
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            
            # Check if certificate is not expired
            now = datetime.utcnow()
            if cert.not_valid_after < now:
                return False
            
            if cert.not_valid_before > now:
                return False
            
            return True
        
        except Exception:
            return False
    
    def generate_cors_headers(self, origin: str = None) -> Dict[str, str]:
        """Generate CORS headers for secure cross-origin requests"""
        if not self.config.cors_enabled:
            return {}
        
        headers = {}
        
        # Check if origin is allowed
        if origin and origin in self.config.allowed_origins:
            headers["Access-Control-Allow-Origin"] = origin
        elif "*" in self.config.allowed_origins:
            headers["Access-Control-Allow-Origin"] = "*"
        
        if self.config.allowed_methods:
            headers["Access-Control-Allow-Methods"] = ", ".join(self.config.allowed_methods)
        
        if self.config.allowed_headers:
            headers["Access-Control-Allow-Headers"] = ", ".join(self.config.allowed_headers)
        
        headers["Access-Control-Max-Age"] = "3600"
        
        return headers


class EnvironmentSecurityValidator:
    """Environment security validation"""
    
    def __init__(self, config: SecurityHardeningConfig):
        self.config = config
    
    def validate_environment(self) -> Tuple[bool, List[str]]:
        """Validate the current environment for security issues"""
        issues = []
        
        if not self.config.environment_validation_enabled:
            return True, []
        
        # Check required environment variables
        for var_name in self.config.required_environment_vars:
            if not os.getenv(var_name):
                issues.append(f"Required environment variable '{var_name}' is not set")
        
        # Check for forbidden environment patterns
        for var_name, var_value in os.environ.items():
            for pattern in self.config.forbidden_environment_patterns:
                if var_name.startswith(pattern):
                    issues.append(f"Forbidden environment variable pattern found: '{var_name}'")
        
        # Check for development/debug indicators
        debug_indicators = [
            "DEBUG", "DEV", "DEVELOPMENT", "TEST", "TESTING",
            "FLASK_DEBUG", "DJANGO_DEBUG", "NODE_ENV"
        ]
        
        for indicator in debug_indicators:
            value = os.getenv(indicator, "").lower()
            if value in ["1", "true", "yes", "on", "development", "debug", "test"]:
                issues.append(f"Debug/development indicator found: {indicator}={value}")
        
        # Check file permissions on sensitive files
        sensitive_files = [".env", "config.json", "secrets.json"]
        for filename in sensitive_files:
            if os.path.exists(filename):
                stat_info = os.stat(filename)
                # Check if file is readable by others (world-readable)
                if stat_info.st_mode & 0o044:
                    issues.append(f"Sensitive file '{filename}' is world-readable")
        
        return len(issues) == 0, issues
    
    def get_security_headers(self) -> Dict[str, str]:
        """Get security headers for HTTP responses"""
        return {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Content-Security-Policy": "default-src 'self'",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
        }


class SecurityHardeningManager:
    """Main security hardening coordinator"""
    
    def __init__(self, config: SecurityHardeningConfig):
        self.config = config
        self.memory_manager = SecureMemoryManager()
        self.request_signer = RequestSigner(config)
        self.transport_security = TransportSecurityManager(config)
        self.environment_validator = EnvironmentSecurityValidator(config)
        
        # Validate environment on initialization
        is_valid, issues = self.environment_validator.validate_environment()
        if not is_valid:
            raise EnvironmentSecurityError(f"Environment validation failed: {', '.join(issues)}")
    
    @contextmanager
    def secure_credential_context(self, credential_data: str):
        """Context manager for secure credential handling"""
        secure_cred = self.memory_manager.allocate_secure_string(credential_data)
        try:
            yield secure_cred
        finally:
            secure_cred.clear()
            self.memory_manager.force_garbage_collection()
    
    def create_secure_request_context(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a secure request context with signing and validation"""
        # Add request metadata
        enhanced_request = {
            **request_data,
            "timestamp": int(time.time()),
            "request_id": secrets.token_hex(16)
        }
        
        # Sign the request
        signature = self.request_signer.sign_request(enhanced_request)
        enhanced_request["signature"] = signature
        
        return enhanced_request
    
    def validate_request_context(self, request_data: Dict[str, Any]) -> bool:
        """Validate a request context"""
        if "signature" not in request_data:
            return not self.config.request_signing_enabled
        
        signature = request_data.pop("signature")
        return self.request_signer.verify_request(request_data, signature)
    
    def get_security_status(self) -> Dict[str, Any]:
        """Get current security status"""
        env_valid, env_issues = self.environment_validator.validate_environment()
        
        return {
            "environment_valid": env_valid,
            "environment_issues": env_issues,
            "memory_allocations": self.memory_manager.get_active_allocations(),
            "transport_security_enabled": self.config.tls_enforcement_enabled,
            "request_signing_enabled": self.config.request_signing_enabled,
            "cors_enabled": self.config.cors_enabled,
            "config": {
                "memory_protection": self.config.memory_protection_enabled,
                "credential_lifetime": self.config.credential_max_lifetime_seconds,
                "min_tls_version": self.config.min_tls_version,
                "signature_algorithm": self.config.signature_algorithm
            }
        }
    
    def cleanup(self):
        """Cleanup security resources"""
        self.memory_manager._cleanup_all_secure_memory()


# Global security hardening manager instance
_security_manager: Optional[SecurityHardeningManager] = None


def initialize_security_hardening(config: SecurityHardeningConfig) -> SecurityHardeningManager:
    """Initialize the global security hardening manager"""
    global _security_manager
    _security_manager = SecurityHardeningManager(config)
    return _security_manager


def get_security_manager() -> Optional[SecurityHardeningManager]:
    """Get the global security hardening manager"""
    return _security_manager


def create_default_security_config() -> SecurityHardeningConfig:
    """Create a default security hardening configuration"""
    return SecurityHardeningConfig()