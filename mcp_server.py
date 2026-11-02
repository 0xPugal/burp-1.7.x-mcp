#!/usr/bin/env python3
"""MCP stdio server that forwards tool calls to the Burp 1.7 "MCP Bridge" extension.

Stdlib only. Env: BURP_MCP_URL (default http://127.0.0.1:8765), BURP_MCP_TOKEN (optional).
"""
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ.get("BURP_MCP_URL", "http://127.0.0.1:8765").rstrip("/")
TOKEN = os.environ.get("BURP_MCP_TOKEN", "")
PROTOCOL = "2024-11-05"


def call_burp(method, path, params=None, body=None):
    url = BASE + path
    if params:
        clean = {k: v for k, v in params.items() if v not in (None, "")}
        if clean:
            url += "?" + urllib.parse.urlencode(clean)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("X-Burp-MCP", "1")
    if TOKEN:
        req.add_header("X-Burp-MCP-Token", TOKEN)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode("utf-8"))
        except Exception:
            return {"error": "HTTP %d" % e.code}
    except urllib.error.URLError as e:
        return {"error": "cannot reach Burp bridge at %s (%s). Is Burp running with the extension loaded?" % (BASE, e.reason)}


REQ_PROPS = {
    "history_id": {"type": "integer", "description": "Use this proxy history item as the base request."},
    "request": {"type": "string", "description": "Raw HTTP request text. With history_id it replaces that item's request but keeps its host/port/scheme. Content-Length is recomputed automatically."},
    "host": {"type": "string", "description": "Target host (only with 'request'; defaults to the Host header)."},
    "port": {"type": "integer", "description": "Target port (only with 'request')."},
    "https": {"type": "boolean", "description": "Use TLS (only with 'request'; default: true if port is 443)."},
    "method": {"type": "string", "description": "HTTP method (with 'url')."},
    "url": {"type": "string", "description": "Absolute http(s) URL; builds the request from method/headers/body."},
    "headers": {"type": "object", "additionalProperties": {"type": "string"}, "description": "Headers (with 'url')."},
    "body": {"type": "string", "description": "Request body (with 'url')."},
}

TOOLS = [
    {
        "name": "burp_history_list",
        "description": "List Burp proxy history items (newest first by default) with id, method, url, status, mime and response length. Use the id with burp_history_get.",
        "inputSchema": {"type": "object", "properties": {
            "limit": {"type": "integer", "description": "Max items (default 50, max 500)."},
            "offset": {"type": "integer", "description": "Skip this many matching items."},
            "host": {"type": "string", "description": "Substring match on host."},
            "method": {"type": "string"},
            "status": {"type": "integer", "description": "Exact response status code."},
            "contains": {"type": "string", "description": "Substring match on URL."},
            "in_scope": {"type": "boolean", "description": "Only items in Burp target scope."},
            "newest_first": {"type": "boolean", "description": "Default true."},
        }},
    },
    {
        "name": "burp_history_get",
        "description": "Get the full request and response of one proxy history item.",
        "inputSchema": {"type": "object", "required": ["id"], "properties": {
            "id": {"type": "integer"},
            "max_chars": {"type": "integer", "description": "Truncate request/response text to this many chars (default 20000)."},
        }},
    },
    {
        "name": "burp_send_request",
        "description": "Send an HTTP request through Burp and return the response. Provide ONE of: history_id (optionally with request to modify it), request (raw text), or method+url(+headers+body).",
        "inputSchema": {"type": "object", "properties": dict(REQ_PROPS, max_chars={"type": "integer", "description": "Truncate output text (default 20000)."})},
    },
    {
        "name": "burp_send_to_repeater",
        "description": "Create a new Burp Repeater tab with the request. With send=true it also clicks Go so the request is actually sent from that tab and the response appears in Burp's Repeater UI (the response is not returned here; use burp_send_request if you need it in the chat). Same inputs as burp_send_request plus caption/send.",
        "inputSchema": {"type": "object", "properties": dict(
            REQ_PROPS,
            caption={"type": "string", "description": "Repeater tab name."},
            send={"type": "boolean", "description": "Click Go after creating the tab (default false)."})},
    },
]


def run_tool(name, a):
    if name == "burp_history_list":
        return call_burp("GET", "/history", {
            "limit": a.get("limit"), "offset": a.get("offset"), "host": a.get("host"),
            "method": a.get("method"), "status": a.get("status"), "contains": a.get("contains"),
            "in_scope": ("1" if a.get("in_scope") else None),
            "newest_first": (None if a.get("newest_first", True) else "0"),
        })
    if name == "burp_history_get":
        return call_burp("GET", "/history/%d" % int(a["id"]), {"max_chars": a.get("max_chars")})
    if name == "burp_send_request":
        return call_burp("POST", "/send", body=a)
    if name == "burp_send_to_repeater":
        return call_burp("POST", "/repeater", body=a)
    return {"error": "unknown tool " + name}


def handle(msg):
    method, mid = msg.get("method"), msg.get("id")
    if mid is None:  # notification
        return None
    if method == "initialize":
        return {"protocolVersion": PROTOCOL, "capabilities": {"tools": {}},
                "serverInfo": {"name": "burp-1.7-mcp", "version": "0.1.0"}}
    if method == "ping":
        return {}
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        p = msg.get("params", {})
        result = run_tool(p.get("name"), p.get("arguments") or {})
        return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}],
                "isError": "error" in result}
    raise KeyError(method)


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        try:
            result = handle(msg)
            if result is None:
                continue
            out = {"jsonrpc": "2.0", "id": msg["id"], "result": result}
        except KeyError:
            out = {"jsonrpc": "2.0", "id": msg.get("id"), "error": {"code": -32601, "message": "method not found"}}
        except Exception as e:
            out = {"jsonrpc": "2.0", "id": msg.get("id"), "error": {"code": -32603, "message": str(e)}}
        sys.stdout.write(json.dumps(out) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
