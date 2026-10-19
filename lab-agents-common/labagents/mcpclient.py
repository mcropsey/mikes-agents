"""Tiny Streamable-HTTP MCP client (stdlib + httpx), enough to drive the lab's demo MCP servers.

Only what agentdemo needs: initialize, tools/list, tools/call. The lab's crapi-mcp server answers with plain
JSON; an SSE (text/event-stream) response is also handled. Session id comes from the Mcp-Session-Id response
header (the crapi-mcp box pins it). Point it at your own lab only.
"""
import json

import httpx

PROTOCOL = "2025-06-18"


class MCPClient:
    def __init__(self, url: str, auth_token: str = "", timeout: int = 60):
        self.url = url
        self.timeout = timeout
        self._id = 0
        self.session_id = ""
        self.server = {}
        headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json",
                   "MCP-Protocol-Version": PROTOCOL}
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"
        self.http = httpx.Client(timeout=timeout, headers=headers, follow_redirects=True)

    # ---- transport ----
    def _rpc(self, method: str, params: dict | None = None, notify: bool = False):
        body = {"jsonrpc": "2.0", "method": method}
        if not notify:
            self._id += 1
            body["id"] = self._id
        if params is not None:
            body["params"] = params
        extra = {"Mcp-Session-Id": self.session_id} if self.session_id else {}
        r = self.http.post(self.url, json=body, headers=extra)
        if not self.session_id and r.headers.get("mcp-session-id"):
            self.session_id = r.headers["mcp-session-id"]
        if notify:
            return None
        r.raise_for_status()
        ctype = r.headers.get("content-type", "")
        if "text/event-stream" in ctype:
            payload = None
            for line in r.text.splitlines():
                if line.startswith("data:"):
                    payload = json.loads(line[5:].strip())
            data = payload or {}
        else:
            data = r.json()
        if isinstance(data, dict) and data.get("error"):
            raise RuntimeError(f"MCP error on {method}: {data['error']}")
        return data.get("result") if isinstance(data, dict) else data

    # ---- lifecycle ----
    def connect(self) -> dict:
        self.server = self._rpc("initialize", {"protocolVersion": PROTOCOL, "capabilities": {},
                                               "clientInfo": {"name": "agentdemo", "version": "1.0"}}) or {}
        self._rpc("notifications/initialized", notify=True)
        return self.server.get("serverInfo", {})

    def list_tools(self) -> list:
        return (self._rpc("tools/list") or {}).get("tools", [])

    def call(self, name: str, arguments: dict | None = None) -> str:
        res = self._rpc("tools/call", {"name": name, "arguments": arguments or {}}) or {}
        parts = []
        for c in res.get("content", []):
            if c.get("type") == "text":
                parts.append(c.get("text", ""))
            else:
                parts.append(json.dumps(c))
        if res.get("isError"):
            return "ERROR: " + ("\n".join(parts) or "tool reported an error")
        return "\n".join(parts) or json.dumps(res)

    def close(self):
        self.http.close()
