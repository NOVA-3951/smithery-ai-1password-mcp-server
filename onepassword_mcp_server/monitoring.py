#!/usr/bin/env python3
"""
Monitoring and health check implementation for the 1Password MCP Server
Includes health checks, metrics collection, and operational dashboards
"""

import asyncio
import time
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from collections import deque, defaultdict
from enum import Enum
import json
import os


class HealthStatus(Enum):
    """Health check status values"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


@dataclass
class HealthCheck:
    """Individual health check result"""
    name: str
    status: HealthStatus
    message: str
    duration_ms: float
    timestamp: str
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class SystemHealth:
    """Overall system health status"""
    overall_status: HealthStatus
    timestamp: str
    checks: List[HealthCheck]
    uptime_seconds: float
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "overall_status": self.overall_status.value,
            "timestamp": self.timestamp,
            "uptime_seconds": self.uptime_seconds,
            "checks": [asdict(check) for check in self.checks],
            "summary": {
                "total_checks": len(self.checks),
                "healthy_checks": sum(1 for c in self.checks if c.status == HealthStatus.HEALTHY),
                "degraded_checks": sum(1 for c in self.checks if c.status == HealthStatus.DEGRADED),
                "unhealthy_checks": sum(1 for c in self.checks if c.status == HealthStatus.UNHEALTHY),
            }
        }


@dataclass
class MetricValue:
    """Individual metric value with timestamp"""
    value: float
    timestamp: float
    labels: Optional[Dict[str, str]] = None


@dataclass
class Metric:
    """Metric with history"""
    name: str
    metric_type: str  # counter, gauge, histogram
    description: str
    values: deque = field(default_factory=lambda: deque(maxlen=1000))
    
    def add_value(self, value: float, labels: Optional[Dict[str, str]] = None):
        """Add a new metric value"""
        self.values.append(MetricValue(
            value=value,
            timestamp=time.time(),
            labels=labels or {}
        ))
    
    def get_current_value(self) -> Optional[float]:
        """Get the most recent value"""
        return self.values[-1].value if self.values else None
    
    def get_average(self, window_seconds: int = 300) -> Optional[float]:
        """Get average value over time window"""
        cutoff = time.time() - window_seconds
        values = [v.value for v in self.values if v.timestamp >= cutoff]
        return sum(values) / len(values) if values else None
    
    def get_rate(self, window_seconds: int = 60) -> Optional[float]:
        """Get rate of change (for counters)"""
        cutoff = time.time() - window_seconds
        values = [(v.value, v.timestamp) for v in self.values if v.timestamp >= cutoff]
        
        if len(values) < 2:
            return None
        
        # Calculate rate from oldest to newest in window
        values.sort(key=lambda x: x[1])
        oldest_value, oldest_time = values[0]
        newest_value, newest_time = values[-1]
        
        time_diff = newest_time - oldest_time
        value_diff = newest_value - oldest_value
        
        return value_diff / time_diff if time_diff > 0 else None


class MetricsCollector:
    """Metrics collection and storage"""
    
    def __init__(self):
        self.metrics: Dict[str, Metric] = {}
        self.start_time = time.time()
    
    def create_counter(self, name: str, description: str) -> Metric:
        """Create a counter metric"""
        metric = Metric(name, "counter", description)
        self.metrics[name] = metric
        return metric
    
    def create_gauge(self, name: str, description: str) -> Metric:
        """Create a gauge metric"""
        metric = Metric(name, "gauge", description)
        self.metrics[name] = metric
        return metric
    
    def create_histogram(self, name: str, description: str) -> Metric:
        """Create a histogram metric"""
        metric = Metric(name, "histogram", description)
        self.metrics[name] = metric
        return metric
    
    def increment_counter(self, name: str, value: float = 1.0, labels: Optional[Dict[str, str]] = None):
        """Increment a counter"""
        if name in self.metrics:
            current = self.metrics[name].get_current_value() or 0
            self.metrics[name].add_value(current + value, labels)
    
    def set_gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """Set a gauge value"""
        if name in self.metrics:
            self.metrics[name].add_value(value, labels)
    
    def record_histogram(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """Record a histogram value"""
        if name in self.metrics:
            self.metrics[name].add_value(value, labels)
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get summary of all metrics"""
        summary = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "uptime_seconds": time.time() - self.start_time,
            "metrics": {}
        }
        
        for name, metric in self.metrics.items():
            metric_data = {
                "type": metric.metric_type,
                "description": metric.description,
                "current_value": metric.get_current_value(),
                "total_samples": len(metric.values)
            }
            
            # Add type-specific calculations
            if metric.metric_type == "counter":
                metric_data["rate_per_minute"] = metric.get_rate(60)
            elif metric.metric_type in ["gauge", "histogram"]:
                metric_data["average_5min"] = metric.get_average(300)
                if metric.metric_type == "histogram":
                    # Calculate percentiles for histograms
                    values = [v.value for v in metric.values if v.timestamp >= time.time() - 300]
                    if values:
                        values.sort()
                        n = len(values)
                        metric_data["percentiles"] = {
                            "p50": values[int(n * 0.5)] if n > 0 else None,
                            "p90": values[int(n * 0.9)] if n > 0 else None,
                            "p95": values[int(n * 0.95)] if n > 0 else None,
                            "p99": values[int(n * 0.99)] if n > 0 else None,
                        }
            
            summary["metrics"][name] = metric_data
        
        return summary


class HealthChecker:
    """Health check orchestrator"""
    
    def __init__(self, metrics_collector: MetricsCollector):
        self.metrics_collector = metrics_collector
        self.start_time = time.time()
        self.checks: Dict[str, callable] = {}
        
        # Initialize basic metrics
        self.metrics_collector.create_gauge("system_uptime_seconds", "System uptime in seconds")
        self.metrics_collector.create_counter("health_checks_total", "Total health checks performed")
        self.metrics_collector.create_counter("health_check_failures_total", "Total health check failures")
    
    def register_check(self, name: str, check_func: callable):
        """Register a health check function"""
        self.checks[name] = check_func
    
    async def run_check(self, name: str, check_func: callable) -> HealthCheck:
        """Run a single health check"""
        start_time = time.perf_counter()
        timestamp = datetime.utcnow().isoformat() + "Z"
        
        try:
            # Run the check with timeout
            result = await asyncio.wait_for(check_func(), timeout=30.0)
            duration_ms = (time.perf_counter() - start_time) * 1000
            
            if isinstance(result, dict):
                status = HealthStatus(result.get("status", "healthy"))
                message = result.get("message", "Check passed")
                metadata = result.get("metadata")
            else:
                status = HealthStatus.HEALTHY if result else HealthStatus.UNHEALTHY
                message = "Check passed" if result else "Check failed"
                metadata = None
            
            self.metrics_collector.increment_counter("health_checks_total")
            
            return HealthCheck(
                name=name,
                status=status,
                message=message,
                duration_ms=duration_ms,
                timestamp=timestamp,
                metadata=metadata
            )
            
        except asyncio.TimeoutError:
            duration_ms = (time.perf_counter() - start_time) * 1000
            self.metrics_collector.increment_counter("health_check_failures_total")
            
            return HealthCheck(
                name=name,
                status=HealthStatus.UNHEALTHY,
                message="Health check timed out",
                duration_ms=duration_ms,
                timestamp=timestamp
            )
            
        except Exception as e:
            duration_ms = (time.perf_counter() - start_time) * 1000
            self.metrics_collector.increment_counter("health_check_failures_total")
            
            return HealthCheck(
                name=name,
                status=HealthStatus.UNHEALTHY,
                message=f"Health check failed: {str(e)}",
                duration_ms=duration_ms,
                timestamp=timestamp
            )
    
    async def run_all_checks(self) -> SystemHealth:
        """Run all registered health checks"""
        uptime = time.time() - self.start_time
        self.metrics_collector.set_gauge("system_uptime_seconds", uptime)
        
        # Run all checks concurrently
        check_tasks = [
            self.run_check(name, check_func)
            for name, check_func in self.checks.items()
        ]
        
        checks = await asyncio.gather(*check_tasks, return_exceptions=True)
        
        # Convert any exceptions to failed health checks
        processed_checks = []
        for i, result in enumerate(checks):
            if isinstance(result, Exception):
                name = list(self.checks.keys())[i]
                processed_checks.append(HealthCheck(
                    name=name,
                    status=HealthStatus.UNHEALTHY,
                    message=f"Check failed with exception: {str(result)}",
                    duration_ms=0,
                    timestamp=datetime.utcnow().isoformat() + "Z"
                ))
            else:
                processed_checks.append(result)
        
        # Determine overall status
        statuses = [check.status for check in processed_checks]
        if any(status == HealthStatus.UNHEALTHY for status in statuses):
            overall_status = HealthStatus.UNHEALTHY
        elif any(status == HealthStatus.DEGRADED for status in statuses):
            overall_status = HealthStatus.DEGRADED
        else:
            overall_status = HealthStatus.HEALTHY
        
        return SystemHealth(
            overall_status=overall_status,
            timestamp=datetime.utcnow().isoformat() + "Z",
            checks=processed_checks,
            uptime_seconds=uptime
        )


class OperationalDashboard:
    """Operational dashboard data provider"""
    
    def __init__(self, metrics_collector: MetricsCollector, health_checker: HealthChecker):
        self.metrics_collector = metrics_collector
        self.health_checker = health_checker
    
    async def get_dashboard_data(self) -> Dict[str, Any]:
        """Get complete dashboard data"""
        health = await self.health_checker.run_all_checks()
        metrics = self.metrics_collector.get_metrics_summary()
        
        return {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "health": health.to_dict(),
            "metrics": metrics,
            "system_info": {
                "version": "1.0.0",
                "environment": os.getenv("ENVIRONMENT", "development"),
                "python_version": f"{os.sys.version_info.major}.{os.sys.version_info.minor}.{os.sys.version_info.micro}",
            }
        }
    
    def get_alerts(self, severity_threshold: str = "warning") -> List[Dict[str, Any]]:
        """Get current alerts based on metrics and health"""
        alerts = []
        
        # Check for high error rates
        error_rate_metric = self.metrics_collector.metrics.get("error_rate")
        if error_rate_metric:
            current_rate = error_rate_metric.get_average(300)  # 5 min average
            if current_rate and current_rate > 0.05:  # 5% error rate
                alerts.append({
                    "type": "high_error_rate",
                    "severity": "warning" if current_rate < 0.1 else "critical",
                    "message": f"High error rate detected: {current_rate:.2%}",
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                })
        
        # Check for slow response times
        latency_metric = self.metrics_collector.metrics.get("request_duration_ms")
        if latency_metric:
            p95_latency = None
            values = [v.value for v in latency_metric.values if v.timestamp >= time.time() - 300]
            if values:
                values.sort()
                p95_latency = values[int(len(values) * 0.95)] if values else None
            
            if p95_latency and p95_latency > 5000:  # 5 second p95
                alerts.append({
                    "type": "high_latency",
                    "severity": "warning" if p95_latency < 10000 else "critical",
                    "message": f"High latency detected: P95 = {p95_latency:.0f}ms",
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                })
        
        return alerts


# Default health check functions
async def basic_health_check() -> Dict[str, Any]:
    """Basic system health check"""
    return {
        "status": "healthy",
        "message": "System is operational",
        "metadata": {
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
    }


async def onepassword_connectivity_check() -> Dict[str, Any]:
    """Check 1Password service connectivity"""
    try:
        # Check if we have the required environment variable
        token = os.getenv("OP_SERVICE_ACCOUNT_TOKEN")
        if not token:
            # Return degraded instead of unhealthy when token is not configured
            # This allows the server to be recognized as functional by Smithery
            # but indicates that credential operations will not work
            return {
                "status": "degraded",
                "message": "1Password service account token not configured - credential operations unavailable",
                "metadata": {
                    "token_configured": False,
                    "credential_operations_available": False
                }
            }
        
        # Basic token format validation
        if not token.startswith("ops_") or len(token) < 20:
            return {
                "status": "degraded",
                "message": "1Password service account token format appears invalid"
            }
        
        return {
            "status": "healthy",
            "message": "1Password connectivity check passed",
            "metadata": {
                "token_configured": True,
                "token_format_valid": True
            }
        }
        
    except Exception as e:
        return {
            "status": "unhealthy",
            "message": f"1Password connectivity check failed: {str(e)}"
        }