# TODO

Status legend: `[x]` implemented, `[~]` implemented but **not yet verified inside real Burp 1.7.37**, `[ ]` not started.
Only `tests/test_pure.py` (pure logic, stubbed Burp) runs without Burp. Everything marked `[~]` needs a manual pass.

## Done
- [x] History list / get (`burp_history_list`, `burp_history_get`) — verified live
- [x] Send request through Burp (`burp_send_request`) — verified live
- [x] Repeater tab + click Go (`burp_send_to_repeater`) — verified live

## Implemented, needs live verification
- [~] History regex search (`burp_history_search`)
- [~] Smart output views: `smart` (binary bodies elided) / `headers` / `raw`
- [~] Site map + scope (`burp_sitemap`, `burp_scope_check`, `burp_scope_update`)
- [~] Request modification (`modify`: method, path, headers, body, replace, set_params via `helpers.updateParameter`)
- [~] `burp_replay_batch` (baseline + up to 50 variants)
- [~] Repeater response return (logger-based; `send=true`, `wait_response`)
- [~] All-tools logger (`burp_log_list`, `burp_log_get`)
- [~] `burp_send_to_intruder` with `§` markers
- [~] Scanner: `burp_scan_active`, `burp_scan_passive`, `burp_scan_status`, `burp_scan_cancel`
- [~] Issues: `burp_issues_list`, `burp_issue_add`
- [~] Collaborator: `burp_collab_payload`, `burp_collab_interactions`
- [~] Cookie jar: `burp_cookies_get`, `burp_cookies_set`
- [~] Annotations: `burp_annotate` (Burp may not persist comment/highlight on history snapshots; the tool reports what it read back)
- [~] Emulated intercept: `burp_intercept_config`, `burp_intercept_pending`, `burp_intercept_resolve`
- [~] Safety: `SCOPE_ONLY`, `HOST_ALLOWLIST`, `ALLOW_INTERCEPT`, optional `TOKEN`; audit trail (`burp_audit`)
- [~] Local tools: `burp_util` (encode/decode/hash/random), `burp_diff`

## Manual verification checklist (do once after loading the extension)
1. `burp_status` returns Burp version and safety settings.
2. `burp_history_search` with a regex that you know exists in a response body.
3. `burp_replay_batch` against a harmless target (e.g. example.com) with 2 header variants.
4. `burp_send_to_repeater` with `send=true` returns a `response` (not just `sent: true`).
5. `burp_send_to_intruder` with a `§`-marked request: positions show in the Intruder tab.
6. `burp_scan_active` on a lab target you own; `burp_scan_status` shows progress.
7. `burp_collab_payload`, hit the hostname with curl, `burp_collab_interactions` shows it.
8. `burp_intercept_config` rule on a test host, browse it, `burp_intercept_pending` lists it, forward/modify/drop.
9. `burp_annotate`: confirm the comment appears in the Proxy history table.
10. Set `SCOPE_ONLY = True`, reload, confirm an out-of-scope send is refused with 403.

## Ideas / not planned
- [ ] Return Repeater/Intruder responses for UI-initiated actions automatically (push, not poll)
- [ ] Session-handling / macro tools (no usable 1.7 API; would need Swing automation)
- [ ] Reading/writing Burp project options (no 1.7 API for this)
- [ ] WebSocket history, HTTP/2 (not supported by Burp 1.7)
- [ ] Persist logger/audit to disk
- [ ] Packaging: Jython-free Java version of the extension
