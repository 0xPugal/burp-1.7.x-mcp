# Burp 1.7.x MCP bridge

Lets Claude Code (or any MCP client) drive **Burp Suite 1.7.37 Pro**, which predates the official PortSwigger MCP server.

```
AI agent --(MCP stdio)--> mcp_server.py --(HTTP, 127.0.0.1:8765)--> burp_mcp_ext.py (inside Burp)
```

## Setup
1. Download the **Jython standalone jar** (2.7.x). Burp → Extender → Options → Python Environment → select it.
2. Extender → Extensions → Add → type **Python** → `burp_mcp_ext.py`. Output tab: `MCP Bridge listening on http://127.0.0.1:8765`.
3. Register the MCP server (Python 3, no dependencies):
   ```bash
   claude mcp add burp -- python C:\Users\Pugalarasan\Music\burp-1.7.x-mcp\mcp_server.py
   ```
   Restart Claude Code; `/mcp` should list `burp`. Optional env: `BURP_MCP_URL`, `BURP_MCP_TOKEN`.

After editing the extension, reload it in Burp (Ctrl+click the *Loaded* checkbox).

## Tools
| Area | Tools |
|---|---|
| Status | `burp_status`, `burp_audit` |
| History | `burp_history_list`, `burp_history_get`, `burp_history_search` (regex) |
| Site map / scope | `burp_sitemap`, `burp_scope_check`, `burp_scope_update` |
| Sending | `burp_send_request`, `burp_replay_batch` |
| Repeater / Intruder | `burp_send_to_repeater` (`send=true` clicks Go and returns the response), `burp_send_to_intruder` (`§` markers) |
| Scanner (Pro) | `burp_scan_active`, `burp_scan_passive`, `burp_scan_status`, `burp_scan_cancel`, `burp_issues_list`, `burp_issue_add` |
| Collaborator (Pro) | `burp_collab_payload`, `burp_collab_interactions` |
| Session | `burp_cookies_get`, `burp_cookies_set` |
| Findings | `burp_annotate` (comment/highlight), `burp_issue_add` |
| All-tools logger | `burp_log_list`, `burp_log_get` |
| Intercept (emulated) | `burp_intercept_config`, `burp_intercept_pending`, `burp_intercept_resolve` |
| Utilities | `burp_util` (url/base64/html/hex/hash/random), `burp_diff` |

Requests can be based on a `history_id`, a `log_id`, a raw `request`, or `method`+`url`, and edited with `modify`
(method, path, headers, body, find/replace, parameters). Content-Length is fixed automatically.

## Safety
- Localhost only; requires header `X-Burp-MCP: 1` (blocks browser CSRF) and a localhost `Host` header (blocks DNS rebinding).
- Constants at the top of `burp_mcp_ext.py`, **not changeable by the agent**: `SCOPE_ONLY`, `HOST_ALLOWLIST`,
  `ALLOW_INTERCEPT`, `INTERCEPT_TIMEOUT`, `TOKEN`. For real engagements set `SCOPE_ONLY = True`.
- Every send/scan/intruder/repeater/scope/intercept action is recorded and readable via `burp_audit`.
- Only test targets you are authorised to test. Scanner and Intruder tools generate attack traffic.

## Development
```bash
python -m unittest discover -s tests -v   # pure-logic tests (Burp stubbed)
```
See `TODO.md` for what is verified in real Burp and what still needs a manual pass, and `CLAUDE.md` for contributor notes.
