"""Entry point — stdio (default), sse, or streamable-http transport mode."""
import os
from pathlib import Path

from dotenv import load_dotenv

# Look for .env in project dir first, then parent (shared Freelance .env)
_here = Path(__file__).parent.parent.parent.parent  # project root
for candidate in (_here / ".env", _here.parent / ".env"):
    if candidate.exists():
        load_dotenv(candidate)
        break
else:
    load_dotenv()  # fall back to CWD / system env


def main() -> None:
    transport = os.environ.get("MCP_TRANSPORT", "stdio")
    port = int(os.environ.get("MCP_PORT", "8080"))

    if transport in ("sse", "streamable-http"):
        from mcp.server.transport_security import TransportSecuritySettings

        from .server import mcp

        mcp.settings.host = "0.0.0.0"
        mcp.settings.port = port
        # Disable DNS rebinding protection — server runs in a trusted container
        mcp.settings.transport_security = TransportSecuritySettings(
            enable_dns_rebinding_protection=False,
        )
        mcp.run(transport=transport)
    else:
        from .server import mcp
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
