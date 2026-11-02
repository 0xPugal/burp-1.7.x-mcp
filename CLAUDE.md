# Burp 1.7.x MCP bridge — notes for agents

Two programs; keep them in sync:

- `burp_mcp_ext.py` — **Jython 2.7** extension running inside Burp Suite 1.7.37 Pro. Localhost HTTP/JSON API.
  Python 2 syntax rules apply: no f-strings, no type hints, no `print()` needed, `unicode`/`long` exist. Uses only the
  legacy Extender API (`IBurpExtender`, ...), never Montoya.
- `mcp_server.py` — **Python 3** stdlib-only MCP stdio server. Thin wrapper over the extension's API, plus local tools
  (`burp_util`, `burp_diff`).

## Adding a feature
1. Add `api_xxx(q, body, arg=None)` in the extension and register it in `ROUTES` (or `PREFIX_ROUTES` for `/x/<id>`).
2. Add the tool to `ROUTES` in `mcp_server.py` (method, path, description, JSON schema).
3. `tests/test_pure.py::test_every_tool_route_exists_in_extension` fails if the two sides drift.
4. Tick it in `TODO.md` (`[~]` until verified in real Burp, then `[x]`).

## Rules
- All raw HTTP is handled as latin-1 text (`to_text` / `to_bytes`) so bytes round-trip. Don't use UTF-8 there.
- Any code path that sends or scans traffic must call `check_target(...)` and `audit(...)`.
- Safety settings (`SCOPE_ONLY`, `HOST_ALLOWLIST`, `ALLOW_INTERCEPT`, `TOKEN`) are constants the agent must not be able to
  change over the API. Never add an endpoint that writes them.
- Keep the `X-Burp-MCP` header + Host check in `Handler._guard` (blocks browser CSRF / DNS rebinding).
- Marker offsets (`§`) must survive CRLF/Content-Length normalisation: use `prepare_with_markers`, not `normalize_raw`.

## Testing
- `python -m unittest discover -s tests -v` — pure logic only (Burp/Java/Jython are stubbed). Run before every commit.
- Anything touching `callbacks`, `helpers`, Swing, the proxy or scanner can only be verified in real Burp: reload the
  extension (Extender > Extensions, Ctrl+click the Loaded box), then call the tool through `mcp_server.py` directly:
  `printf '<json-rpc lines>' | python mcp_server.py`. Burp must be running; the bridge is on 127.0.0.1:8765.
- A new Claude Code session is needed to see changed tool schemas (MCP tools load at session start).

## Known limits (Burp 1.7 API)
No HTTP/2, no WebSocket history, no intercept toggle (we emulate by holding in `processProxyMessage`), no project
options access. Repeater "Go" is clicked through Swing component search (`_click_go`); it is the most fragile part.
Scanner, Collaborator and cookie jar need Burp Pro.
