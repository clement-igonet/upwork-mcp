# OCI image — compatible with Apple's container tool (macOS 26+) and Docker
FROM python:3.12-slim

WORKDIR /app

# Install uv for fast dependency resolution
RUN pip install --no-cache-dir uv

# Copy project files
COPY pyproject.toml uv.lock* ./
COPY src/ src/

# Install dependencies via uv (no venv — system install inside container)
RUN uv pip install --system --no-cache .

# SSE transport so Claude Desktop can connect over TCP
ENV MCP_TRANSPORT=sse
ENV MCP_PORT=8080

EXPOSE 8080

CMD ["python", "-m", "upwork_mcp"]
