"""
Signet MCP Proxy — Wraps upstream MCP servers with policy enforcement.

Claude Code connects to this proxy instead of directly to MCP servers.
Every tool call passes through the policy engine before being forwarded.
The agent has no direct connection to bypass.

Config at ~/.signet/proxy.yaml:
  servers:
    linear:
      command: npx
      args: ["-y", "mcp-linear"]
      env:
        LINEAR_API_KEY: "lin_api_..."
    github:
      command: gh
      args: ["mcp"]

The proxy:
1. Starts all upstream servers as child processes
2. Collects their tool lists (prefixed with server name)
3. Exposes all tools through a single MCP server
4. Intercepts every call_tool: evaluate policy → forward or deny → log
"""

import asyncio
import json
import logging
import os
import sys
import yaml
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any

from mcp import StdioServerParameters, ClientSession
from mcp.client.stdio import stdio_client
from mcp.server.fastmcp import FastMCP
from mcp.types import TextContent

logger = logging.getLogger(__name__)

PROXY_CONFIG = Path.home() / ".signet" / "proxy.yaml"


def _load_proxy_config() -> dict:
    """Load proxy configuration listing upstream servers."""
    if not PROXY_CONFIG.exists():
        return {"servers": {}}
    return yaml.safe_load(PROXY_CONFIG.read_text()) or {"servers": {}}


class UpstreamServer:
    """A connected upstream MCP server."""

    def __init__(self, name: str, session: ClientSession, tools: list):
        self.name = name
        self.session = session
        self.tools = tools  # list of mcp.types.Tool
        # Map of proxied_name -> original_name
        self.tool_map = {}
        for t in tools:
            proxied = f"{name}__{t.name}"
            self.tool_map[proxied] = t.name


class SignetProxy:
    """MCP proxy server with policy enforcement."""

    def __init__(self):
        self.mcp = FastMCP("signet-proxy", instructions="""This is a Signet-proxied MCP server.
All tool calls pass through policy enforcement. Some tools may be denied or require confirmation
based on the user's policy at ~/.signet/policy.yaml.""")
        self.upstreams: dict[str, UpstreamServer] = {}
        self._exit_stack = AsyncExitStack()
        self._vault = None

    async def _connect_upstream(self, name: str, config: dict) -> UpstreamServer:
        """Connect to an upstream MCP server."""
        params = StdioServerParameters(
            command=config["command"],
            args=config.get("args", []),
            env=config.get("env"),
        )

        stdio_transport = await self._exit_stack.enter_async_context(
            stdio_client(params)
        )
        read_stream, write_stream = stdio_transport
        session = await self._exit_stack.enter_async_context(
            ClientSession(read_stream, write_stream)
        )
        await session.initialize()

        tools_result = await session.list_tools()
        tools = tools_result.tools

        upstream = UpstreamServer(name, session, tools)
        logger.info(f"Connected to {name}: {len(tools)} tools")
        return upstream

    def _evaluate_policy(self, tool_name: str, arguments: dict) -> tuple[str, str]:
        """Evaluate policy for a tool call. Returns (decision, reason)."""
        from signet_eval_tool.signet_eval_tool import (
            ToolUseRequest, evaluate_request, load_policy, get_default_policy,
            PolicyParseError, RegexCompileError, Decision,
        )

        try:
            policy = load_policy()
        except (PolicyParseError, RegexCompileError):
            policy = get_default_policy()

        try:
            request = ToolUseRequest(
                tool_name=tool_name,
                parameters=arguments or {},
                context={},
            )
        except Exception:
            return "deny", "Invalid tool call"

        result = evaluate_request(request, policy, vault=self._vault)
        return result.decision.value.lower(), result.reason or ""

    def _log_action(self, tool_name: str, arguments: dict, decision: str):
        """Log action to vault if available."""
        if not self._vault:
            return
        try:
            amount = float((arguments or {}).get("amount", 0))
            category = str((arguments or {}).get("category", ""))
            self._vault.log_action(
                tool=tool_name,
                decision=decision.upper(),
                category=category,
                amount=amount if decision == "allow" else 0.0,
                detail=json.dumps(arguments or {})[:500],
            )
        except Exception:
            pass

    def _register_proxied_tools(self):
        """Register all upstream tools on the proxy server."""
        for upstream in self.upstreams.values():
            for tool in upstream.tools:
                proxied_name = f"{upstream.name}__{tool.name}"
                original_name = tool.name
                server_name = upstream.name

                # Build the tool function dynamically
                self._register_one_tool(proxied_name, original_name, server_name, tool)

    def _register_one_tool(self, proxied_name: str, original_name: str,
                           server_name: str, tool):
        """Register a single proxied tool."""
        upstream = self.upstreams[server_name]
        description = tool.description or f"Proxied from {server_name}"
        input_schema = tool.inputSchema if hasattr(tool, 'inputSchema') else {}

        @self.mcp.tool(name=proxied_name, description=f"[{server_name}] {description}")
        async def proxied_call(**kwargs) -> str:
            # Evaluate policy
            decision, reason = self._evaluate_policy(proxied_name, kwargs)

            if decision == "deny":
                self._log_action(proxied_name, kwargs, "deny")
                return f"DENIED by Signet policy: {reason}"

            if decision == "ask":
                self._log_action(proxied_name, kwargs, "ask")
                return f"REQUIRES APPROVAL: {reason}. This action was blocked pending user confirmation."

            # Forward to upstream
            try:
                result = await upstream.session.call_tool(original_name, kwargs)
                self._log_action(proxied_name, kwargs, "allow")

                # Extract text content
                parts = []
                for content in result.content:
                    if isinstance(content, TextContent):
                        parts.append(content.text)
                    elif hasattr(content, 'text'):
                        parts.append(content.text)
                    else:
                        parts.append(str(content))
                return "\n".join(parts) if parts else "(empty response)"

            except Exception as e:
                self._log_action(proxied_name, kwargs, "error")
                return f"Error calling {server_name}/{original_name}: {e}"

    async def start(self):
        """Connect to all upstream servers and start the proxy."""
        config = _load_proxy_config()

        # Try to load vault
        from signet_eval_tool.signet_eval_tool import _try_load_vault
        self._vault = _try_load_vault()

        # Connect to upstreams
        for name, server_config in config.get("servers", {}).items():
            try:
                upstream = await self._connect_upstream(name, server_config)
                self.upstreams[name] = upstream
            except Exception as e:
                logger.error(f"Failed to connect to {name}: {e}")

        if not self.upstreams:
            logger.warning("No upstream servers connected. Proxy will have no tools.")

        # Register all proxied tools
        self._register_proxied_tools()

        total_tools = sum(len(u.tools) for u in self.upstreams.values())
        logger.info(f"Proxy ready: {len(self.upstreams)} servers, {total_tools} tools")

    async def shutdown(self):
        """Disconnect from all upstream servers."""
        await self._exit_stack.aclose()


async def _run_proxy():
    """Start the proxy server."""
    proxy = SignetProxy()
    await proxy.start()
    proxy.mcp.run(transport="stdio")


def main():
    """Entry point for signet-proxy command."""
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)

    config = _load_proxy_config()
    servers = config.get("servers", {})

    if not servers:
        print("No upstream servers configured.", file=sys.stderr)
        print(f"Create {PROXY_CONFIG} with:", file=sys.stderr)
        print("""
servers:
  linear:
    command: npx
    args: ["-y", "mcp-linear"]
    env:
      LINEAR_API_KEY: "your-key"
""", file=sys.stderr)
        sys.exit(1)

    asyncio.run(_run_proxy())


if __name__ == "__main__":
    main()
