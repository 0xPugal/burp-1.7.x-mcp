# Burp 1.7.x MCP bridge

```
Claude Code / AI agent --(MCP stdio)--> mcp_server.py --(HTTP, 127.0.0.1:8765)--> burp_mcp_ext.py (inside Burp 1.7.37)
```

## 1. Load the extension in Burp
1. Download the **Jython standalone jar** (2.7.x) from jython.org.
2. Burp → Extender → Options → Python Environment → select the jar.
3. Extender → Extensions → Add → type **Python** → pick `burp_mcp_ext.py`.
4. Output tab should say `MCP Bridge listening on http://127.0.0.1:8765`.

Port/token are constants at the top of `burp_mcp_ext.py`.

## 2. Register the MCP server (Python 3, no dependencies)
```bash
claude mcp add burp -- python C:\Users\Pugalarasan\Music\burp-1.7.x-mcp\mcp_server.py
```
Optional env: `BURP_MCP_URL`, `BURP_MCP_TOKEN` (must match `TOKEN` in the extension).

## Tools
| tool | what |
|---|---|
| `burp_history_list` | filter proxy history (host, method, status, url substring, scope) |
| `burp_history_get` | full request/response of a history id |
| `burp_send_request` | send via Burp; from `history_id`, raw `request`, or `method`+`url` |
| `burp_send_to_repeater` | open a new Repeater tab (not sent) |

Tip: `burp_send_request` with `history_id` + a modified `request` replays a captured
request's host/scheme with your edits. Content-Length is fixed automatically.

## Security
The bridge binds to localhost only, requires a custom `X-Burp-MCP` header (blocks
browser CSRF) and checks the Host header (blocks DNS rebinding). Anything that can
reach it can make Burp send requests, so set `TOKEN` on shared machines.
