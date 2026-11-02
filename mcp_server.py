#!/usr/bin/env python3
"""MCP stdio server that forwards tool calls to the Burp 1.7 "MCP Bridge" extension.

Stdlib only. Env: BURP_MCP_URL (default http://127.0.0.1:8765), BURP_MCP_TOKEN (optional).
Most tools are thin wrappers over the extension's HTTP API (see ROUTES); burp_util and
burp_diff run locally.
"""
import base64
import difflib
import hashlib
import html
import json
import os
import random
import string
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
        with urllib.request.urlopen(req, timeout=180) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode("utf-8"))
        except Exception:
            return {"error": "HTTP %d" % e.code}
    except urllib.error.URLError as e:
        return {"error": "cannot reach Burp bridge at %s (%s). Is Burp running with the extension loaded?" % (BASE, e.reason)}


# --------------------------------------------------------------------------- schemas
def obj(props, required=None):
    s = {"type": "object", "properties": props}
    if required:
        s["required"] = required
    return s


INT, STR, BOOL = {"type": "integer"}, {"type": "string"}, {"type": "boolean"}


def t(desc, **kw):
    return dict(kw, description=desc)


MODIFY = {
    "type": "object",
    "description": "Edit the base request before sending. All keys optional.",
    "properties": {
        "method": STR, "path": t("New request-target, e.g. /api/users/2", type="string"),
        "set_headers": {"type": "object", "additionalProperties": STR},
        "remove_headers": {"type": "array", "items": STR},
        "body": t("Replace the whole body.", type="string"),
        "replace": {"type": "array", "description": "Find/replace on the raw request.",
                    "items": obj({"find": STR, "replace": STR, "regex": BOOL}, ["find"])},
        "set_params": {"type": "array", "description": "Add or update parameters (values are URL-encoded unless raw=true).",
                       "items": obj({"name": STR, "value": STR, "type": t("url|body|cookie|json (default url)", type="string"),
                                     "raw": BOOL}, ["name", "value"])},
    },
}

TARGET_PROPS = {
    "history_id": t("Base the request on this proxy history item.", type="integer"),
    "log_id": t("Base the request on this logger entry (burp_log_list).", type="integer"),
    "request": t("Raw HTTP request text. With history_id/log_id it replaces that request but keeps its host/port/scheme. Content-Length is fixed automatically.", type="string"),
    "host": t("Target host (only with 'request' alone; defaults to Host header).", type="string"),
    "port": INT,
    "https": t("Use TLS (only with 'request' alone; default: true if port 443).", type="boolean"),
    "method": STR,
    "url": t("Absolute http(s) URL; builds a request from method/headers/body.", type="string"),
    "headers": {"type": "object", "additionalProperties": STR},
    "body": STR,
    "modify": MODIFY,
}
VIEW = t("smart (default; binary bodies elided) | headers | raw", type="string")
MAXC = t("Truncate message text to this many chars (default 20000).", type="integer")
FILTERS = {
    "host": t("Substring of host.", type="string"), "method": STR,
    "status": t("Exact code (200) or class (4xx).", type="string"),
    "contains": t("Substring of URL.", type="string"),
    "in_scope": t("Only items in Burp scope.", type="boolean"),
}

# name: (HTTP method, path template, description, schema)
ROUTES = {
    "burp_status": ("GET", "/ping", "Bridge status: Burp version, history size, safety settings (scope-only, host allowlist), intercept state.", obj({})),
    "burp_history_list": ("GET", "/history", "List Burp proxy history (newest first) with id, method, url, status, mime, length, comment. Use id with burp_history_get.",
                          obj(dict(FILTERS, limit=INT, offset=INT, newest_first=BOOL))),
    "burp_history_get": ("GET", "/history/{id}", "Full request and response of one proxy history item.",
                         obj({"id": INT, "view": VIEW, "max_chars": MAXC}, ["id"])),
    "burp_history_search": ("GET", "/history/search", "Regex-search proxy history requests/responses (like grep). Returns matching ids with snippets.",
                            obj(dict(FILTERS, regex=STR, where=t("all (default)|url|request|response|headers|body", type="string"),
                                     case=t("Case-sensitive (default false).", type="boolean"),
                                     context=t("Snippet chars around a match (default 60).", type="integer"), limit=INT), ["regex"])),
    "burp_sitemap": ("GET", "/sitemap", "List Burp's site map (optionally under a URL prefix).",
                     obj(dict(FILTERS, prefix=t("URL prefix, e.g. https://example.com/api", type="string"), limit=INT, offset=INT))),
    "burp_scope_check": ("GET", "/scope", "Check whether a URL is in Burp's target scope.", obj({"url": STR}, ["url"])),
    "burp_scope_update": ("POST", "/scope", "Add/remove URLs (prefixes) to/from Burp's target scope.",
                          obj({"include": {"type": "array", "items": STR}, "exclude": {"type": "array", "items": STR}})),
    "burp_send_request": ("POST", "/send", "Send an HTTP request through Burp and return the response. Base: history_id | log_id | request | method+url; optional modify edits it.",
                          obj(dict(TARGET_PROPS, view=VIEW, max_chars=MAXC))),
    "burp_replay_batch": ("POST", "/replay_batch", "Send a baseline plus up to 50 modified variants of one request and compare status/length/time (IDOR, auth-swap, parameter fuzz). Sequential.",
                          obj(dict(TARGET_PROPS,
                                   variants={"type": "array", "items": obj({"label": STR, "modify": MODIFY})},
                                   delay_ms=INT, snippet_chars=t("Include this many body chars per variant (default 0).", type="integer")), ["variants"])),
    "burp_send_to_repeater": ("POST", "/repeater", "Create a Burp Repeater tab. With send=true it clicks Go and (wait_response, default true) returns the response captured by the logger.",
                              obj(dict(TARGET_PROPS, caption=STR, send=BOOL, wait_response=BOOL,
                                       timeout=t("Seconds to wait for the response (default 15).", type="integer"), view=VIEW, max_chars=MAXC))),
    "burp_send_to_intruder": ("POST", "/intruder", "Send a request to Intruder. Mark payload positions with section signs: GET /?id=§1§. Does not start the attack.",
                              obj(dict(TARGET_PROPS, insertion_points=t("Alternative to § markers: [[start,end],...] byte offsets.", type="array", items={"type": "array", "items": INT})))),
    "burp_scan_active": ("POST", "/scan/active", "Start an active scan (Pro) of one request. Use § markers to limit insertion points. Returns scan_id.", obj(TARGET_PROPS)),
    "burp_scan_passive": ("POST", "/scan/passive", "Run a passive scan (Pro) over a history item's stored response.", obj({"history_id": INT}, ["history_id"])),
    "burp_scan_status": ("GET", "/scan/status", "Status/progress of one scan (id) or all scans started via this bridge.", obj({"id": INT})),
    "burp_scan_cancel": ("POST", "/scan/cancel", "Cancel a scan started via this bridge.", obj({"id": INT}, ["id"])),
    "burp_issues_list": ("GET", "/issues", "List Burp scanner issues (Pro).",
                         obj({"prefix": STR, "severity": t("High|Medium|Low|Information", type="string"), "confidence": STR,
                              "name": t("Substring of issue name.", type="string"),
                              "detail": t("Include description/remediation text.", type="boolean"), "limit": INT, "offset": INT})),
    "burp_issue_add": ("POST", "/issues", "Add a custom issue to Burp's issue list, attached to a history item (records a finding).",
                       obj({"history_id": INT, "name": STR, "detail": STR, "remediation": STR,
                            "severity": t("High|Medium|Low|Information", type="string"),
                            "confidence": t("Certain|Firm|Tentative", type="string")}, ["history_id", "name"])),
    "burp_collab_payload": ("POST", "/collab/payload", "Generate a Burp Collaborator payload hostname (Pro).", obj({})),
    "burp_collab_interactions": ("GET", "/collab/interactions", "Poll Collaborator interactions (DNS/HTTP/SMTP) for a payload, or all (Pro).", obj({"payload": t("payload_id or hostname from burp_collab_payload", type="string")})),
    "burp_cookies_get": ("GET", "/cookies", "Read Burp's cookie jar.", obj({"domain": t("Substring of domain.", type="string")})),
    "burp_cookies_set": ("POST", "/cookies", "Add/update a cookie in Burp's cookie jar.",
                         obj({"domain": STR, "name": STR, "value": STR, "path": STR, "expires_ms": INT}, ["domain", "name", "value"])),
    "burp_annotate": ("POST", "/annotate", "Set a comment and/or highlight colour on a proxy history item.",
                      obj({"history_id": INT, "comment": STR, "highlight": t("red|orange|yellow|green|cyan|blue|pink|magenta|gray", type="string")}, ["history_id"])),
    "burp_log_list": ("GET", "/log", "List traffic from ALL Burp tools (repeater, scanner, intruder, extender; not proxy) from an in-memory ring buffer (last 1000).",
                      obj({"tool": t("repeater|scanner|intruder|extender|...", type="string"), "host": STR, "contains": STR, "status": STR, "limit": INT, "offset": INT})),
    "burp_log_get": ("GET", "/log/{id}", "Full request/response of a logger entry.", obj({"id": INT, "view": VIEW, "max_chars": MAXC}, ["id"])),
    "burp_intercept_config": ("POST", "/intercept/config", "Emulated intercept: hold matching proxy messages for the agent to forward/modify/drop. Call with no args to read state. Rules need host, url_regex or method; direction request|response|both. Held messages auto-forward after timeout seconds.",
                              obj({"enabled": BOOL, "timeout": INT,
                                   "rules": {"type": "array", "items": obj({"host": STR, "url_regex": STR, "method": STR, "direction": STR})}})),
    "burp_intercept_pending": ("GET", "/intercept/pending", "List proxy messages currently held by the emulated intercept.", obj({"max_chars": INT})),
    "burp_intercept_resolve": ("POST", "/intercept/resolve", "Forward (optionally with an edited request/response) or drop a held message.",
                               obj({"id": INT, "action": t("forward|drop", type="string"), "request": STR, "response": STR}, ["id"])),
    "burp_audit": ("GET", "/audit", "Audit trail of every action the agent performed through the bridge.", obj({"limit": INT})),
}


# --------------------------------------------------------------------------- local tools
UTIL_OPS = ["url_encode", "url_decode", "base64_encode", "base64_decode", "html_encode", "html_decode",
            "hex_encode", "hex_decode", "md5", "sha1", "sha256", "random_string"]


def util(op, value="", length=16, charset="alnum"):
    b = value.encode("utf-8", "surrogateescape")
    if op == "url_encode":
        return urllib.parse.quote(value, safe="")
    if op == "url_decode":
        return urllib.parse.unquote(value)
    if op == "base64_encode":
        return base64.b64encode(b).decode()
    if op == "base64_decode":
        return base64.b64decode(value + "=" * (-len(value) % 4)).decode("utf-8", "replace")
    if op == "html_encode":
        return html.escape(value)
    if op == "html_decode":
        return html.unescape(value)
    if op == "hex_encode":
        return b.hex()
    if op == "hex_decode":
        return bytes.fromhex(value).decode("utf-8", "replace")
    if op in ("md5", "sha1", "sha256"):
        return hashlib.new(op, b).hexdigest()
    if op == "random_string":
        pool = {"alnum": string.ascii_letters + string.digits, "alpha": string.ascii_letters,
                "digits": string.digits, "hex": "0123456789abcdef"}.get(charset)
        if pool is None:
            raise ValueError("charset: alnum|alpha|digits|hex")
        return "".join(random.SystemRandom().choice(pool) for _ in range(max(1, min(int(length), 4096))))
    raise ValueError("op must be one of " + ", ".join(UTIL_OPS))


def fetch_ref(ref, part):
    kind, _, num = ref.partition(":")
    if kind not in ("history", "log") or not num.isdigit():
        return None, "ref must look like history:12 or log:5"
    res = call_burp("GET", "/%s/%s" % (kind, num), {"view": "raw", "max_chars": 2000000})
    if "error" in res:
        return None, res["error"]
    return res.get(part), None


def diff_tool(a, b, part="response", context=3, max_lines=400):
    ta, ea = fetch_ref(a, part)
    tb, eb = fetch_ref(b, part)
    if ea or eb:
        return {"error": ea or eb}
    if ta is None or tb is None:
        return {"error": "one side has no %s" % part}
    la, lb = ta.replace("\r\n", "\n").split("\n"), tb.replace("\r\n", "\n").split("\n")
    lines = list(difflib.unified_diff(la, lb, a, b, lineterm="", n=context))
    return {"identical": ta == tb, "a_chars": len(ta), "b_chars": len(tb),
            "diff": "\n".join(lines[:max_lines]) + ("\n...[diff truncated]" if len(lines) > max_lines else "")}


LOCAL_TOOLS = {
    "burp_util": ("Encode/decode/hash/random helpers: " + ", ".join(UTIL_OPS) + ".",
                  obj({"op": t("One of: " + ", ".join(UTIL_OPS), type="string"), "value": STR, "length": INT,
                       "charset": t("alnum|alpha|digits|hex (random_string)", type="string")}, ["op"]),
                  lambda a: {"result": util(a["op"], a.get("value", ""), a.get("length", 16), a.get("charset", "alnum"))}),
    "burp_diff": ("Unified diff of two messages. Refs are 'history:<id>' or 'log:<id>' (e.g. compare a baseline and a replayed response).",
                  obj({"a": t("history:12 or log:5", type="string"), "b": STR,
                       "part": t("response (default) | request", type="string"), "context": INT}, ["a", "b"]),
                  lambda a: diff_tool(a["a"], a["b"], a.get("part", "response"), int(a.get("context", 3)))),
}

TOOLS = [{"name": n, "description": d, "inputSchema": s} for n, (_m, _p, d, s) in ROUTES.items()]
TOOLS += [{"name": n, "description": d, "inputSchema": s} for n, (d, s, _f) in LOCAL_TOOLS.items()]


def run_tool(name, args):
    args = dict(args)
    if name in LOCAL_TOOLS:
        try:
            return LOCAL_TOOLS[name][2](args)
        except (ValueError, KeyError) as e:
            return {"error": "%s: %s" % (e.__class__.__name__, e)}
    if name not in ROUTES:
        return {"error": "unknown tool " + name}
    method, path, _d, _s = ROUTES[name]
    if "{id}" in path:
        if "id" not in args:
            return {"error": "'id' is required"}
        path = path.replace("{id}", str(int(args.pop("id"))))
    if method == "GET":
        params = {k: ("1" if v is True else "0" if v is False else v) for k, v in args.items()}
        return call_burp("GET", path, params)
    return call_burp("POST", path, body=args)


def handle(msg):
    method, mid = msg.get("method"), msg.get("id")
    if mid is None:  # notification
        return None
    if method == "initialize":
        return {"protocolVersion": PROTOCOL, "capabilities": {"tools": {}},
                "serverInfo": {"name": "burp-1.7-mcp", "version": "0.2.0"}}
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
