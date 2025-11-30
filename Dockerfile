# Dockerfile for 1Password MCP Server - Smithery Deployment
# Use uv-enhanced Python image for fast builds
FROM ghcr.io/astral-sh/uv:python3.12-alpine

WORKDIR /app

# Set environment variables for uv
ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy

# Install dependencies using lockfile and pyproject.toml
# Use cache mounts for faster rebuilds
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-dev

# Copy the application code
COPY onepassword_mcp_server /app/onepassword_mcp_server

# Set default port (will be overridden by Smithery)
ENV PORT=8081

# Expose the port
EXPOSE ${PORT}

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:${PORT}/health')" || exit 1

# Run the server in streamable HTTP mode
CMD ["uv", "run", "python", "-m", "onepassword_mcp_server.server", "--transport", "streamable-http"]
