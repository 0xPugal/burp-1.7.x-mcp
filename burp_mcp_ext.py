# -*- coding: utf-8 -*-
# Burp Suite 1.7.x Pro extension (Jython 2.7). Exposes Burp over a localhost-only
# HTTP/JSON API; mcp_server.py wraps that API as an MCP server.
#
# All requests need header "X-Burp-MCP: 1" (and X-Burp-MCP-Token if TOKEN is set).
# Routes are listed in ROUTES at the bottom of the API section.

from burp import (IBurpExtender, IExtensionStateListener, IHttpListener, IProxyListener,
                  ICookie, IScanIssue, IHttpRequestResponse)
from java.lang import String, Runnable
from java.awt import Container, Frame
from java.net import URL
from java.util import ArrayList, Date
from javax.swing import JButton, JTabbedPane, SwingUtilities
from jarray import array as jarray
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from SocketServer import ThreadingMixIn
from urlparse import urlparse, parse_qs
import collections
import fnmatch
import json
import re
import threading
import time

# ----------------------------------------------------------------------------
# Config. Safety settings are constants on purpose: the agent can read them
# (/ping) but cannot change them. Edit here and reload the extension.
# ----------------------------------------------------------------------------
HOST = "127.0.0.1"
PORT = 8765
TOKEN = ""                 # optional shared secret (header X-Burp-MCP-Token)
SCOPE_ONLY = False         # if True, refuse to send/scan anything outside Burp's target scope
HOST_ALLOWLIST = []        # e.g. ["*.example.com", "10.0.0.5"]; empty = no host restriction
ALLOW_INTERCEPT = True     # allow the agent to hold proxy traffic (emulated intercept)
INTERCEPT_TIMEOUT = 30     # seconds a held message waits before being auto-forwarded
LOG_MAX = 1000             # ring buffer size for the all-tools logger
LOG_PROXY = False          # proxy traffic is already in proxy history
LOG_BODY_MAX = 1000000     # per message bytes kept in the logger
DEFAULT_MAX_CHARS = 20000
LATIN1 = "ISO-8859-1"

TOOL_NAMES = {1: "suite", 2: "target", 4: "proxy", 8: "spider", 16: "scanner", 32: "intruder",
              64: "repeater", 128: "sequencer", 256: "decoder", 512: "comparer", 1024: "extender"}
PARAM_TYPES = {"url": 0, "body": 1, "cookie": 2, "xml": 3, "json": 6}
HIGHLIGHTS = ("red", "orange", "yellow", "green", "cyan", "blue", "pink", "magenta", "gray")

EXT = None


# ----------------------------------------------------------------------------
# Text / bytes helpers (latin-1 keeps arbitrary bytes lossless)
# ----------------------------------------------------------------------------
def to_text(byte_array):
    if byte_array is None:
        return u""
    return unicode(String(byte_array, LATIN1))


def to_bytes(text):
    return String(text).getBytes(LATIN1)


def clip(text, max_chars):
    if max_chars and len(text) > max_chars:
        return text[:max_chars] + "\n...[truncated %d of %d chars]" % (max_chars, len(text))
    return text


def strip_html(text):
    if not text:
        return text
    text = re.sub(r"(?i)<br\s*/?>|</p>|</li>", "\n", text)
    text = re.sub(r"<[^>]+>", "", text)
    return text.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").strip()


class ApiError(Exception):
    def __init__(self, status, message):
        Exception.__init__(self, message)
        self.status = status
        self.message = message


def qget(q, key, default=""):
    v = q.get(key)
    return v[0] if v else default


def qbool(q, key, default=False):
    v = q.get(key)
    if not v:
        return default
    return v[0].lower() in ("1", "true", "yes")


def split_message(text):
    """(head, body) of a raw HTTP message; body is '' when there is none."""
    m = re.search(r"\r?\n\r?\n", text)
    if m:
        return text[:m.start()], text[m.end():]
    return text, u""


def looks_binary(head, body):
    m = re.search(r"(?im)^content-type\s*:\s*([^\r\n;]+)", head)
    ctype = m.group(1).strip().lower() if m else ""
    if ctype.startswith(("image/", "audio/", "video/", "font/")) or ctype in (
            "application/octet-stream", "application/zip", "application/pdf",
            "application/gzip", "application/x-protobuf"):
        return True
    sample = body[:2000]
    if not sample:
        return False
    if u"\x00" in sample:
        return True
    bad = sum(1 for c in sample if ord(c) < 9 or 13 < ord(c) < 32)
    return bad * 10 > len(sample)


def render(byte_array, max_chars, view="smart"):
    """view: smart (binary bodies elided), headers, raw."""
    text = to_text(byte_array)
    if view == "raw":
        return clip(text, max_chars)
    head, body = split_message(text)
    if view == "headers":
        return clip(head, max_chars)
    if body and looks_binary(head, body):
        body = u"[binary body omitted: %d bytes]" % len(body)
    return clip(head + u"\r\n\r\n" + body, max_chars)


# ----------------------------------------------------------------------------
# Raw request building / editing
# ----------------------------------------------------------------------------
def crlf_head(raw):
    """Convert the head's line endings to CRLF and ensure a blank line ends it."""
    m = re.search(r"\r?\n\r?\n", raw)
    if m:
        head, body = raw[:m.start()], raw[m.end():]
    else:
        head, body = raw, u""
    return re.sub(r"\r?\n", u"\r\n", head) + u"\r\n\r\n" + body


def set_content_length(raw):
    """Fix Content-Length in place. Returns (raw, position_of_change, delta)."""
    idx = raw.find(u"\r\n\r\n")
    head, body = raw[:idx], raw[idx + 4:]
    lines = head.split(u"\r\n")
    method = lines[0].split(u" ", 1)[0].upper()
    blen = len(to_bytes(body))
    want = bool(body) or method in (u"POST", u"PUT", u"PATCH")
    pos, delta, found = idx, 0, False
    out = []
    offset = 0
    for i, line in enumerate(lines):
        if i > 0 and re.match(r"(?i)content-length\s*:", line):
            found = True
            if want:
                new = u"Content-Length: %d" % blen
                pos, delta = offset, len(new) - len(line)
                out.append(new)
            else:
                pos, delta = offset, -(len(line) + 2)
        else:
            out.append(line)
        offset += len(line) + 2
    if want and not found:
        out.append(u"Content-Length: %d" % blen)
        pos, delta = idx, len(out[-1]) + 2
    return u"\r\n".join(out) + u"\r\n\r\n" + body, pos, delta


def normalize_raw(raw):
    return set_content_length(crlf_head(raw))[0]


def strip_markers(raw):
    """Intruder-style section-sign markers: a§b§c -> (abc, [[start,end]])."""
    parts = raw.split(u"\u00a7")
    if len(parts) < 3 or len(parts) % 2 == 0:
        return raw, None
    clean, offsets = u"", []
    for i, p in enumerate(parts):
        if i % 2 == 1:
            offsets.append([len(clean), len(clean) + len(p)])
        clean += p
    return clean, offsets


def prepare_with_markers(raw):
    """CRLF + Content-Length normalisation that keeps marker offsets valid."""
    raw = crlf_head(raw)
    clean, offsets = strip_markers(raw)
    fixed, pos, delta = set_content_length(clean)
    if offsets and delta:
        offsets = [[s + (delta if s > pos else 0), e + (delta if s > pos else 0)]
                   for s, e in offsets]
    return fixed, offsets


def apply_modify(raw, mods):
    """Edit a raw request: method/path/headers/body/replace/params."""
    h = EXT.helpers
    text = crlf_head(raw)
    for r in mods.get("replace") or []:
        if r.get("regex"):
            text = re.sub(r["find"], r.get("replace", ""), text)
        else:
            text = text.replace(r["find"], r.get("replace", ""))
    idx = text.find(u"\r\n\r\n")
    head, body = text[:idx], text[idx + 4:]
    lines = head.split(u"\r\n")
    if mods.get("method") or mods.get("path"):
        parts = lines[0].split(u" ", 2)
        while len(parts) < 3:
            parts.append(u"HTTP/1.1")
        if mods.get("method"):
            parts[0] = mods["method"].upper()
        if mods.get("path"):
            parts[1] = mods["path"]
        lines[0] = u" ".join(parts)
    remove = [k.lower() for k in (mods.get("remove_headers") or [])]
    if remove:
        lines = lines[:1] + [l for l in lines[1:]
                             if l.split(u":", 1)[0].strip().lower() not in remove]
    for k, v in (mods.get("set_headers") or {}).items():
        new, done = [lines[0]], False
        for l in lines[1:]:
            if l.split(u":", 1)[0].strip().lower() == k.lower():
                if not done:
                    new.append(u"%s: %s" % (k, v))
                    done = True
            else:
                new.append(l)
        if not done:
            new.append(u"%s: %s" % (k, v))
        lines = new
    if mods.get("body") is not None:
        body = mods["body"]
    text = u"\r\n".join(lines) + u"\r\n\r\n" + body
    if mods.get("set_params"):
        req = to_bytes(text)
        for p in mods["set_params"]:
            ptype = PARAM_TYPES.get(p.get("type", "url"))
            if ptype is None:
                raise ApiError(400, "param type must be one of %s" % sorted(PARAM_TYPES))
            name, val = p["name"], p["value"]
            if ptype in (0, 1) and not p.get("raw"):
                val = h.urlEncode(val)
            exists = False
            for ex in h.analyzeRequest(req).getParameters():
                if ex.getName() == name and ex.getType() == ptype:
                    exists = True
                    break
            newp = h.buildParameter(name, val, ptype)
            req = h.updateParameter(req, newp) if exists else h.addParameter(req, newp)
        text = to_text(req)
    return text


def build_from_parts(spec):
    url = spec.get("url")
    if not url:
        raise ApiError(400, "need 'request', 'history_id', 'log_id' or 'method'+'url'")
    u = urlparse(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ApiError(400, "url must be absolute http(s)")
    https = u.scheme == "https"
    port = u.port or (443 if https else 80)
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    method = (spec.get("method") or "GET").upper()
    headers = spec.get("headers") or {}
    names = [k.lower() for k in headers]
    lines = [u"%s %s HTTP/1.1" % (method, path)]
    if "host" not in names:
        default = (https and port == 443) or (not https and port == 80)
        lines.append(u"Host: %s" % (u.hostname if default else "%s:%d" % (u.hostname, port)))
    for k, v in headers.items():
        lines.append(u"%s: %s" % (k, v))
    raw = u"\r\n".join(lines) + u"\r\n\r\n" + (spec.get("body") or u"")
    return u.hostname, port, https, raw


def log_find(seq):
    with EXT.log_lock:
        for e in EXT.log:
            if e["seq"] == seq:
                return e
    return None


def resolve_target(spec, final=True):
    """(host, port, https, raw) from history_id | log_id | request | method+url,
    then spec['modify'] applied. final=False skips normalisation (marker callers)."""
    callbacks = EXT.callbacks
    host = port = https = None
    raw = None
    if spec.get("history_id") is not None:
        hist = callbacks.getProxyHistory()
        idx = int(spec["history_id"])
        if idx < 0 or idx >= len(hist):
            raise ApiError(404, "no history item %d" % idx)
        svc = hist[idx].getHttpService()
        host, port, https = svc.getHost(), svc.getPort(), svc.getProtocol() == "https"
        raw = to_text(hist[idx].getRequest())
    elif spec.get("log_id") is not None:
        e = log_find(int(spec["log_id"]))
        if e is None:
            raise ApiError(404, "no log entry %s" % spec["log_id"])
        host, port, https = e["host"], e["port"], e["https"]
        raw = to_text(e["request"])
    if spec.get("request"):
        raw = spec["request"]  # overrides the request of a history/log base, keeping its target
        if host is None:
            host, port, https = spec.get("host"), spec.get("port"), spec.get("https")
            if not host:
                m = re.search(r"(?im)^host\s*:\s*([^\r\n]+)", raw)
                if not m:
                    raise ApiError(400, "no 'host' given and no Host header in request")
                hv = m.group(1).strip()
                if ":" in hv and not hv.endswith("]"):
                    hv, p = hv.rsplit(":", 1)
                    port = port or int(p)
                host = hv
            if https is None:
                https = (port == 443)
            if not port:
                port = 443 if https else 80
    if raw is None:
        host, port, https, raw = build_from_parts(spec)
    if spec.get("modify"):
        raw = apply_modify(raw, spec["modify"])
    if final:
        raw = normalize_raw(raw)
    return host, int(port), bool(https), raw


def url_of(host, port, https, raw):
    m = re.match(r"\S+\s+(\S+)", raw)
    path = m.group(1) if m else "/"
    try:
        if path.lower().startswith("http"):
            return URL(path)
        default = (https and port == 443) or (not https and port == 80)
        netloc = host if default else "%s:%d" % (host, port)
        return URL("%s://%s%s" % ("https" if https else "http", netloc, path))
    except Exception:
        raise ApiError(400, "cannot build URL from request line")


def audit(action, **info):
    entry = {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "action": action}
    entry.update(info)
    EXT.audit_log.append(entry)


def check_target(host, port, https, raw):
    if HOST_ALLOWLIST and not any(fnmatch.fnmatch(host.lower(), p.lower()) for p in HOST_ALLOWLIST):
        raise ApiError(403, "host %s not in HOST_ALLOWLIST" % host)
    if SCOPE_ONLY and not EXT.callbacks.isInScope(url_of(host, port, https, raw)):
        raise ApiError(403, "target is outside Burp scope (SCOPE_ONLY is on)")


# ----------------------------------------------------------------------------
# Summaries
# ----------------------------------------------------------------------------
def summarize(idx, item):
    helpers = EXT.helpers
    req = helpers.analyzeRequest(item)
    svc = item.getHttpService()
    resp = item.getResponse()
    out = {
        "id": idx,
        "method": req.getMethod(),
        "url": req.getUrl().toString(),
        "host": svc.getHost(),
        "port": svc.getPort(),
        "https": svc.getProtocol() == "https",
        "status": None,
        "mime": None,
        "response_length": None,
    }
    if resp is not None:
        ar = helpers.analyzeResponse(resp)
        out["status"] = ar.getStatusCode()
        out["mime"] = ar.getStatedMimeType()
        out["response_length"] = len(resp)
    comment = item.getComment()
    if comment:
        out["comment"] = comment
    return out


def status_matches(want, status):
    if not want:
        return True
    if status is None:
        return False
    if want.lower().endswith("xx"):
        return str(status).startswith(want[0])
    return str(status) == want


def history_filter(q):
    callbacks = EXT.callbacks
    host = qget(q, "host").lower()
    method = qget(q, "method").upper()
    status = qget(q, "status")
    contains = qget(q, "contains").lower()
    in_scope = qbool(q, "in_scope")

    def ok(s, item):
        if host and host not in s["host"].lower():
            return False
        if method and s["method"] != method:
            return False
        if not status_matches(status, s["status"]):
            return False
        if contains and contains not in s["url"].lower():
            return False
        if in_scope and not callbacks.isInScope(EXT.helpers.analyzeRequest(item).getUrl()):
            return False
        return True
    return ok


# ----------------------------------------------------------------------------
# API: status
# ----------------------------------------------------------------------------
def api_ping(q, body, arg=None):
    return {
        "ok": True,
        "burp": list(EXT.callbacks.getBurpVersion()),
        "history_size": len(EXT.callbacks.getProxyHistory()),
        "log_size": len(EXT.log),
        "safety": {"scope_only": SCOPE_ONLY, "host_allowlist": HOST_ALLOWLIST,
                   "allow_intercept": ALLOW_INTERCEPT, "token_required": bool(TOKEN)},
        "intercept": {"enabled": EXT.intercept["enabled"], "rules": EXT.intercept["rules"],
                      "timeout": EXT.intercept["timeout"], "pending": len(EXT.pending)},
    }


# ----------------------------------------------------------------------------
# API: proxy history, search, site map, scope
# ----------------------------------------------------------------------------
def api_history(q, body, arg=None):
    offset = int(qget(q, "offset", "0"))
    limit = min(int(qget(q, "limit", "50")), 500)
    newest_first = qbool(q, "newest_first", True)
    ok = history_filter(q)
    hist = EXT.callbacks.getProxyHistory()
    total = len(hist)
    order = range(total - 1, -1, -1) if newest_first else range(total)
    matched, skipped = [], 0
    for i in order:
        s = summarize(i, hist[i])
        if not ok(s, hist[i]):
            continue
        if skipped < offset:
            skipped += 1
            continue
        matched.append(s)
        if len(matched) >= limit:
            break
    return {"total_history": total, "returned": len(matched), "items": matched}


def api_history_item(q, body, arg=None):
    idx = int(arg)
    hist = EXT.callbacks.getProxyHistory()
    if idx < 0 or idx >= len(hist):
        raise ApiError(404, "no history item %d" % idx)
    max_chars = int(qget(q, "max_chars", str(DEFAULT_MAX_CHARS)))
    view = qget(q, "view", "smart")
    item = hist[idx]
    out = summarize(idx, item)
    out["request"] = render(item.getRequest(), max_chars, view)
    resp = item.getResponse()
    out["response"] = render(resp, max_chars, view) if resp is not None else None
    return out


def api_history_search(q, body, arg=None):
    pattern = qget(q, "regex")
    if not pattern:
        raise ApiError(400, "'regex' is required")
    try:
        rx = re.compile(pattern, 0 if qbool(q, "case") else re.I)
    except re.error as e:
        raise ApiError(400, "bad regex: %s" % e)
    where = qget(q, "where", "all")
    ctx = int(qget(q, "context", "60"))
    limit = min(int(qget(q, "limit", "25")), 200)
    ok = history_filter(q)
    hist = EXT.callbacks.getProxyHistory()
    results, scanned = [], 0
    for i in range(len(hist) - 1, -1, -1):
        s = summarize(i, hist[i])
        if not ok(s, hist[i]):
            continue
        scanned += 1
        rq = to_text(hist[i].getRequest())[:LOG_BODY_MAX]
        rs = to_text(hist[i].getResponse())[:LOG_BODY_MAX]
        rqh, rqb = split_message(rq)
        rsh, rsb = split_message(rs)
        sources = {
            "url": [("url", s["url"])],
            "request": [("request", rq)],
            "response": [("response", rs)],
            "headers": [("request_headers", rqh), ("response_headers", rsh)],
            "body": [("request_body", rqb), ("response_body", rsb)],
            "all": [("request", rq), ("response", rs)],
        }.get(where)
        if sources is None:
            raise ApiError(400, "where must be url|request|response|headers|body|all")
        snippets = []
        for label, text in sources:
            for m in rx.finditer(text):
                snippets.append({"in": label,
                                 "text": text[max(0, m.start() - ctx):m.end() + ctx]})
                if len(snippets) >= 3:
                    break
            if len(snippets) >= 3:
                break
        if snippets:
            s["matches"] = snippets
            results.append(s)
            if len(results) >= limit:
                break
    return {"scanned": scanned, "returned": len(results), "items": results}


def api_sitemap(q, body, arg=None):
    prefix = qget(q, "prefix") or None
    offset = int(qget(q, "offset", "0"))
    limit = min(int(qget(q, "limit", "100")), 1000)
    ok = history_filter(q)
    items = EXT.callbacks.getSiteMap(prefix)
    out, skipped = [], 0
    for it in items:
        s = summarize(None, it)
        if not ok(s, it):
            continue
        if skipped < offset:
            skipped += 1
            continue
        out.append(s)
        if len(out) >= limit:
            break
    return {"total": len(items), "returned": len(out), "items": out}


def _to_url(u):
    try:
        return URL(u)
    except Exception:
        raise ApiError(400, "bad URL: %s" % u)


def api_scope_check(q, body, arg=None):
    u = qget(q, "url")
    if not u:
        raise ApiError(400, "'url' is required")
    return {"url": u, "in_scope": bool(EXT.callbacks.isInScope(_to_url(u)))}


def api_scope_update(q, body, arg=None):
    inc = body.get("include") or []
    exc = body.get("exclude") or []
    for u in inc:
        EXT.callbacks.includeInScope(_to_url(u))
    for u in exc:
        EXT.callbacks.excludeFromScope(_to_url(u))
    audit("scope", include=inc, exclude=exc)
    return {"ok": True, "included": inc, "excluded": exc}


# ----------------------------------------------------------------------------
# API: sending, replay, repeater, intruder
# ----------------------------------------------------------------------------
def do_send(host, port, https, raw, max_chars=DEFAULT_MAX_CHARS, view="smart"):
    check_target(host, port, https, raw)
    t0 = time.time()
    resp = EXT.callbacks.makeHttpRequest(host, port, https, to_bytes(raw))
    elapsed = int((time.time() - t0) * 1000)
    audit("send", host=host, port=port, https=https, line=raw.split(u"\r\n", 1)[0][:200])
    out = {"host": host, "port": port, "https": https, "elapsed_ms": elapsed,
           "request": clip(raw, max_chars)}
    if resp is None or len(resp) == 0:
        out["response"] = None
        out["error"] = "no response (connection failed or timed out)"
        return out
    out["status"] = EXT.helpers.analyzeResponse(resp).getStatusCode()
    out["response_length"] = len(resp)
    out["response"] = render(resp, max_chars, view)
    return out


def api_send(q, body, arg=None):
    host, port, https, raw = resolve_target(body)
    return do_send(host, port, https, raw, int(body.get("max_chars", DEFAULT_MAX_CHARS)),
                   body.get("view", "smart"))


def api_replay_batch(q, body, arg=None):
    variants = body.get("variants") or []
    if not variants or len(variants) > 50:
        raise ApiError(400, "'variants' must hold 1-50 entries")
    delay = float(body.get("delay_ms", 0)) / 1000.0
    snippet = int(body.get("snippet_chars", 0))
    base_spec = dict((k, v) for k, v in body.items() if k not in ("variants", "delay_ms", "snippet_chars"))
    host, port, https, raw = resolve_target(base_spec)
    baseline = do_send(host, port, https, raw, 0)
    base_len = baseline.get("response_length")
    base_status = baseline.get("status")
    base_body = split_message(baseline.get("response") or u"")[1]
    results = [{"label": "baseline", "status": base_status, "response_length": base_len,
                "elapsed_ms": baseline["elapsed_ms"]}]
    for i, v in enumerate(variants):
        spec = dict(base_spec)
        mods = dict(base_spec.get("modify") or {})
        mods.update(v.get("modify") or {})
        spec["modify"] = mods
        label = v.get("label") or "variant %d" % (i + 1)
        try:
            h2, p2, s2, r2 = resolve_target(spec)
            res = do_send(h2, p2, s2, r2, 0)
        except ApiError as e:
            results.append({"label": label, "error": e.message})
            continue
        row = {"label": label, "status": res.get("status"),
               "response_length": res.get("response_length"), "elapsed_ms": res["elapsed_ms"],
               "status_differs": res.get("status") != base_status,
               "length_delta": (res.get("response_length") or 0) - (base_len or 0)}
        if res.get("error"):
            row["error"] = res["error"]
        if snippet and res.get("response"):
            row["body_snippet"] = clip(split_message(res["response"])[1], snippet)
        results.append(row)
        if delay:
            time.sleep(delay)
    return {"target": "%s:%d" % (host, port), "results": results}


def _walk(comp, kind, out):
    if isinstance(comp, kind):
        out.append(comp)
    if isinstance(comp, Container):
        for c in comp.getComponents():
            _walk(c, kind, out)


def _click_go(caption):
    """Runs on the Swing EDT. Click Go in the Repeater tab titled `caption`."""
    for frame in Frame.getFrames():
        panes = []
        _walk(frame, JTabbedPane, panes)
        for outer in panes:
            ri = outer.indexOfTab("Repeater")
            if ri < 0:
                continue
            inner_panes = []
            _walk(outer.getComponentAt(ri), JTabbedPane, inner_panes)
            for inner in inner_panes:
                if inner is outer:
                    continue
                idx = -1
                for i in range(inner.getTabCount()):
                    if inner.getTitleAt(i) == caption:
                        idx = i
                if idx < 0:
                    continue
                buttons = []
                _walk(inner.getComponentAt(idx), JButton, buttons)
                for b in buttons:
                    if (b.getText() or "").strip() == "Go":
                        b.doClick()
                        return True
    return False


class _EdtTask(Runnable):
    def __init__(self, caption):
        self.caption = caption
        self.result = False

    def run(self):
        self.result = _click_go(self.caption)


def click_repeater_go(caption, attempts=30, delay=0.1):
    # Burp builds the tab asynchronously, so retry for ~3 seconds
    for _ in range(attempts):
        task = _EdtTask(caption)
        SwingUtilities.invokeAndWait(task)
        if task.result:
            return True
        time.sleep(delay)
    return False


def wait_for_log(seq0, tool, host, timeout):
    end = time.time() + timeout
    while time.time() < end:
        with EXT.log_lock:
            for e in EXT.log:
                if e["seq"] > seq0 and e["tool"] == tool and e["host"].lower() == host.lower():
                    return e
        time.sleep(0.1)
    return None


def api_repeater(q, body, arg=None):
    host, port, https, raw = resolve_target(body)
    check_target(host, port, https, raw)
    send = bool(body.get("send"))
    caption = body.get("caption") or "MCP"
    if send:
        caption = "%s-%d" % (caption, int(time.time() * 1000) % 100000)
    seq0 = EXT.log_seq
    EXT.callbacks.sendToRepeater(host, port, https, to_bytes(raw), caption)
    audit("repeater", host=host, caption=caption, send=send)
    out = {"ok": True, "host": host, "port": port, "https": https, "caption": caption, "sent": False}
    if not send:
        return out
    out["sent"] = click_repeater_go(caption)
    if not out["sent"]:
        out["warning"] = ("tab created but the Go button could not be found/clicked; "
                          "press Go manually in the Repeater tab")
        return out
    if body.get("wait_response", True):
        e = wait_for_log(seq0, "repeater", host, float(body.get("timeout", 15)))
        max_chars = int(body.get("max_chars", DEFAULT_MAX_CHARS))
        if e is None:
            out["warning"] = "Go was clicked but no Repeater response was seen within the timeout"
        else:
            out["log_id"] = e["seq"]
            out["status"] = e["status"]
            out["response_length"] = e["response_length"]
            out["response"] = render(e["response"], max_chars, body.get("view", "smart"))
    return out


def api_intruder(q, body, arg=None):
    host, port, https, raw = resolve_target(body, final=False)
    raw, offsets = prepare_with_markers(raw)
    check_target(host, port, https, raw)
    if offsets is None and body.get("insertion_points"):
        offsets = body["insertion_points"]
    if offsets:
        pts = ArrayList()
        for s, e in offsets:
            pts.add(jarray([int(s), int(e)], "i"))
        EXT.callbacks.sendToIntruder(host, port, https, to_bytes(raw), pts)
    else:
        EXT.callbacks.sendToIntruder(host, port, https, to_bytes(raw))
    audit("intruder", host=host, positions=len(offsets or []))
    return {"ok": True, "host": host, "port": port, "https": https,
            "positions": len(offsets or []), "note": "request sent to Intruder; start the attack in the UI"}


# ----------------------------------------------------------------------------
# API: scanner (Pro), issues
# ----------------------------------------------------------------------------
def api_scan_active(q, body, arg=None):
    host, port, https, raw = resolve_target(body, final=False)
    raw, offsets = prepare_with_markers(raw)
    check_target(host, port, https, raw)
    try:
        if offsets:
            pts = ArrayList()
            for s, e in offsets:
                pts.add(jarray([int(s), int(e)], "i"))
            item = EXT.callbacks.doActiveScan(host, port, https, to_bytes(raw), pts)
        else:
            item = EXT.callbacks.doActiveScan(host, port, https, to_bytes(raw))
    except Exception as e:
        raise ApiError(500, "active scan failed (Burp Pro required): %s" % e)
    EXT.scan_seq += 1
    EXT.scans[EXT.scan_seq] = {"item": item, "target": "%s:%d" % (host, port),
                               "line": raw.split(u"\r\n", 1)[0][:200]}
    audit("scan_active", host=host, scan_id=EXT.scan_seq)
    return {"ok": True, "scan_id": EXT.scan_seq, "target": "%s:%d" % (host, port),
            "insertion_points": "custom (%d)" % len(offsets) if offsets else "automatic"}


def api_scan_passive(q, body, arg=None):
    if body.get("history_id") is None:
        raise ApiError(400, "'history_id' is required (needs a stored response)")
    hist = EXT.callbacks.getProxyHistory()
    idx = int(body["history_id"])
    if idx < 0 or idx >= len(hist):
        raise ApiError(404, "no history item %d" % idx)
    item = hist[idx]
    if item.getResponse() is None:
        raise ApiError(400, "history item has no response")
    svc = item.getHttpService()
    EXT.callbacks.doPassiveScan(svc.getHost(), svc.getPort(), svc.getProtocol() == "https",
                                item.getRequest(), item.getResponse())
    audit("scan_passive", history_id=idx)
    return {"ok": True, "history_id": idx}


def scan_dict(sid, rec):
    it = rec["item"]
    d = {"scan_id": sid, "target": rec["target"], "request_line": rec["line"]}
    for key, fn in (("status", "getStatus"), ("percent_complete", "getPercentageComplete"),
                    ("requests", "getNumRequests"), ("errors", "getNumErrors"),
                    ("insertion_points", "getNumInsertionPoints")):
        try:
            d[key] = getattr(it, fn)()
        except Exception:
            d[key] = None
    try:
        d["issues_found"] = len(it.getIssues())
    except Exception:
        d["issues_found"] = None
    return d


def api_scan_status(q, body, arg=None):
    sid = qget(q, "id")
    if sid:
        rec = EXT.scans.get(int(sid))
        if rec is None:
            raise ApiError(404, "no scan %s" % sid)
        return scan_dict(int(sid), rec)
    return {"scans": [scan_dict(k, v) for k, v in sorted(EXT.scans.items())]}


def api_scan_cancel(q, body, arg=None):
    rec = EXT.scans.get(int(body.get("id", -1)))
    if rec is None:
        raise ApiError(404, "no such scan")
    rec["item"].cancel()
    audit("scan_cancel", scan_id=body["id"])
    return {"ok": True}


def issue_dict(i, issue, detail):
    d = {"index": i, "name": issue.getIssueName(), "severity": issue.getSeverity(),
         "confidence": issue.getConfidence(), "url": issue.getUrl().toString(),
         "type": "0x%08x" % issue.getIssueType()}
    if detail:
        d["detail"] = strip_html(issue.getIssueDetail())
        d["background"] = strip_html(issue.getIssueBackground())
        d["remediation"] = strip_html(issue.getRemediationDetail() or issue.getRemediationBackground())
    return d


def api_issues(q, body, arg=None):
    prefix = qget(q, "prefix") or None
    sev = qget(q, "severity").lower()
    conf = qget(q, "confidence").lower()
    name = qget(q, "name").lower()
    detail = qbool(q, "detail")
    offset = int(qget(q, "offset", "0"))
    limit = min(int(qget(q, "limit", "50")), 500)
    issues = EXT.callbacks.getScanIssues(prefix)
    out, skipped = [], 0
    for i, iss in enumerate(issues):
        if sev and iss.getSeverity().lower() != sev:
            continue
        if conf and iss.getConfidence().lower() != conf:
            continue
        if name and name not in iss.getIssueName().lower():
            continue
        if skipped < offset:
            skipped += 1
            continue
        out.append(issue_dict(i, iss, detail))
        if len(out) >= limit:
            break
    return {"total": len(issues), "returned": len(out), "items": out}


class CustomIssue(IScanIssue):
    def __init__(self, url, name, detail, severity, confidence, remediation, msgs, svc):
        self._url, self._name, self._detail = url, name, detail
        self._sev, self._conf, self._rem = severity, confidence, remediation
        self._msgs, self._svc = msgs, svc

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0x08000000  # extension-generated issue

    def getSeverity(self):
        return self._sev

    def getConfidence(self):
        return self._conf

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return self._rem

    def getHttpMessages(self):
        return self._msgs

    def getHttpService(self):
        return self._svc


def api_issue_add(q, body, arg=None):
    sev = body.get("severity", "Information").capitalize()
    conf = body.get("confidence", "Tentative").capitalize()
    if sev not in ("High", "Medium", "Low", "Information"):
        raise ApiError(400, "severity: High|Medium|Low|Information")
    if conf not in ("Certain", "Firm", "Tentative"):
        raise ApiError(400, "confidence: Certain|Firm|Tentative")
    if not body.get("name") or body.get("history_id") is None:
        raise ApiError(400, "'name' and 'history_id' are required")
    hist = EXT.callbacks.getProxyHistory()
    idx = int(body["history_id"])
    if idx < 0 or idx >= len(hist):
        raise ApiError(404, "no history item %d" % idx)
    item = hist[idx]
    url = EXT.helpers.analyzeRequest(item).getUrl()
    detail = (body.get("detail") or "").replace("&", "&amp;").replace("<", "&lt;").replace("\n", "<br>")
    issue = CustomIssue(url, body["name"], detail, sev, conf, body.get("remediation"),
                        jarray([item], IHttpRequestResponse), item.getHttpService())
    EXT.callbacks.addScanIssue(issue)
    audit("issue_add", name=body["name"], history_id=idx)
    return {"ok": True, "url": url.toString(), "severity": sev, "confidence": conf}


# ----------------------------------------------------------------------------
# API: Collaborator, cookies, annotations
# ----------------------------------------------------------------------------
def collab_ctx():
    if EXT.collab is None:
        try:
            EXT.collab = EXT.callbacks.createBurpCollaboratorClientContext()
        except Exception as e:
            raise ApiError(500, "Collaborator unavailable (Burp Pro required): %s" % e)
    return EXT.collab


def api_collab_payload(q, body, arg=None):
    ctx = collab_ctx()
    p = ctx.generatePayload(False)
    loc = ctx.getCollaboratorServerLocation()
    audit("collab_payload", payload=p)
    return {"payload_id": p, "hostname": "%s.%s" % (p, loc), "server": loc}


def api_collab_interactions(q, body, arg=None):
    ctx = collab_ctx()
    pid = qget(q, "payload")
    if pid:
        evs = ctx.fetchCollaboratorInteractionsFor(pid.split(".")[0])
    else:
        evs = ctx.fetchAllCollaboratorInteractions()
    out = []
    for ev in evs:
        props = dict((k, v) for k, v in ev.getProperties().items())
        for key in ("request", "response", "raw_query", "conversation"):
            if key in props:
                try:
                    props[key] = clip(to_text(EXT.helpers.base64Decode(props[key])), 4000)
                except Exception:
                    pass
        out.append(props)
    return {"count": len(out), "interactions": out}


class Cookie(ICookie):
    def __init__(self, domain, path, name, value, expires):
        self._d, self._p, self._n, self._v, self._e = domain, path, name, value, expires

    def getDomain(self):
        return self._d

    def getPath(self):
        return self._p

    def getName(self):
        return self._n

    def getValue(self):
        return self._v

    def getExpiration(self):
        return self._e


def api_cookies_get(q, body, arg=None):
    domain = qget(q, "domain").lower()
    out = []
    for c in EXT.callbacks.getCookieJarContents():
        d = c.getDomain() or ""
        if domain and domain not in d.lower():
            continue
        exp = c.getExpiration()
        out.append({"domain": d, "path": c.getPath(), "name": c.getName(),
                    "value": c.getValue(), "expires": exp.toString() if exp else None})
    return {"count": len(out), "cookies": out}


def api_cookies_set(q, body, arg=None):
    for k in ("domain", "name", "value"):
        if not body.get(k):
            raise ApiError(400, "'%s' is required" % k)
    exp = Date(long(body["expires_ms"])) if body.get("expires_ms") else None
    EXT.callbacks.updateCookieJar(Cookie(body["domain"], body.get("path", "/"),
                                         body["name"], body["value"], exp))
    audit("cookie_set", domain=body["domain"], name=body["name"])
    return {"ok": True}


def api_annotate(q, body, arg=None):
    hist = EXT.callbacks.getProxyHistory()
    idx = int(body.get("history_id", -1))
    if idx < 0 or idx >= len(hist):
        raise ApiError(404, "no history item %s" % body.get("history_id"))
    item = hist[idx]
    if body.get("comment") is not None:
        item.setComment(body["comment"])
    if body.get("highlight"):
        if body["highlight"] not in HIGHLIGHTS:
            raise ApiError(400, "highlight must be one of %s" % ", ".join(HIGHLIGHTS))
        item.setHighlight(body["highlight"])
    audit("annotate", history_id=idx)
    now = EXT.callbacks.getProxyHistory()[idx]
    return {"ok": True, "comment": now.getComment(), "highlight": now.getHighlight(),
            "note": "if comment/highlight are empty, Burp did not persist the change to history"}


# ----------------------------------------------------------------------------
# API: all-tools logger and audit trail
# ----------------------------------------------------------------------------
def log_summary(e):
    return {"id": e["seq"], "tool": e["tool"], "time": e["time"], "method": e["method"],
            "url": e["url"], "host": e["host"], "status": e["status"],
            "response_length": e["response_length"]}


def api_log(q, body, arg=None):
    tool = qget(q, "tool").lower()
    host = qget(q, "host").lower()
    contains = qget(q, "contains").lower()
    status = qget(q, "status")
    offset = int(qget(q, "offset", "0"))
    limit = min(int(qget(q, "limit", "50")), 500)
    with EXT.log_lock:
        entries = list(EXT.log)
    entries.reverse()
    out, skipped = [], 0
    for e in entries:
        if tool and e["tool"] != tool:
            continue
        if host and host not in e["host"].lower():
            continue
        if contains and contains not in e["url"].lower():
            continue
        if not status_matches(status, e["status"]):
            continue
        if skipped < offset:
            skipped += 1
            continue
        out.append(log_summary(e))
        if len(out) >= limit:
            break
    return {"buffered": len(entries), "returned": len(out), "items": out}


def api_log_item(q, body, arg=None):
    e = log_find(int(arg))
    if e is None:
        raise ApiError(404, "log entry %s not in buffer" % arg)
    max_chars = int(qget(q, "max_chars", str(DEFAULT_MAX_CHARS)))
    view = qget(q, "view", "smart")
    out = log_summary(e)
    out["request"] = render(e["request"], max_chars, view)
    out["response"] = render(e["response"], max_chars, view) if e["response"] is not None else None
    return out


def api_audit(q, body, arg=None):
    limit = min(int(qget(q, "limit", "50")), 500)
    items = list(EXT.audit_log)[-limit:]
    items.reverse()
    return {"count": len(items), "items": items}


# ----------------------------------------------------------------------------
# API: emulated intercept
# ----------------------------------------------------------------------------
def rule_matches(rule, is_req, method, url, host):
    d = rule.get("direction", "request")
    if d == "request" and not is_req:
        return False
    if d == "response" and is_req:
        return False
    if rule.get("host") and rule["host"].lower() not in host.lower():
        return False
    if rule.get("method") and rule["method"].upper() != method:
        return False
    if rule.get("url_regex") and not re.search(rule["url_regex"], url):
        return False
    return True


def api_intercept_config(q, body, arg=None):
    st = EXT.intercept
    if body:
        if not ALLOW_INTERCEPT:
            raise ApiError(403, "ALLOW_INTERCEPT is off")
        if "rules" in body:
            for r in body["rules"]:
                if not (r.get("host") or r.get("url_regex") or r.get("method")):
                    raise ApiError(400, "each rule needs at least one of host, url_regex, method")
                if r.get("direction", "request") not in ("request", "response", "both"):
                    raise ApiError(400, "direction must be request|response|both")
                if r.get("url_regex"):
                    re.compile(r["url_regex"])
            st["rules"] = body["rules"]
        if "timeout" in body:
            st["timeout"] = max(1, min(int(body["timeout"]), 300))
        if "enabled" in body:
            st["enabled"] = bool(body["enabled"])
            if not st["enabled"]:
                with EXT.pend_lock:
                    for p in EXT.pending.values():
                        p["decision"] = {"action": "forward"}
                        p["event"].set()
        audit("intercept_config", enabled=st["enabled"], rules=st["rules"])
    return {"enabled": st["enabled"], "rules": st["rules"], "timeout": st["timeout"],
            "pending": len(EXT.pending)}


def api_intercept_pending(q, body, arg=None):
    max_chars = int(qget(q, "max_chars", "8000"))
    out = []
    with EXT.pend_lock:
        items = sorted(EXT.pending.items())
    for pid, p in items:
        d = {"id": pid, "direction": p["direction"], "method": p["method"], "url": p["url"],
             "expires_in": max(0, int(p["deadline"] - time.time())),
             "request": render(p["request"], max_chars)}
        if p["response"] is not None:
            d["response"] = render(p["response"], max_chars)
        out.append(d)
    return {"count": len(out), "items": out}


def api_intercept_resolve(q, body, arg=None):
    pid = int(body.get("id", -1))
    action = body.get("action", "forward")
    if action not in ("forward", "drop"):
        raise ApiError(400, "action must be forward|drop")
    with EXT.pend_lock:
        p = EXT.pending.get(pid)
    if p is None:
        raise ApiError(404, "no pending message %s (already resolved or timed out)" % pid)
    p["decision"] = {"action": action, "request": body.get("request"),
                     "response": body.get("response")}
    p["event"].set()
    audit("intercept_resolve", id=pid, action=action, modified=bool(body.get("request") or body.get("response")))
    return {"ok": True, "id": pid, "action": action}


# ----------------------------------------------------------------------------
# Routing
# ----------------------------------------------------------------------------
ROUTES = {
    ("GET", "/ping"): api_ping,
    ("GET", "/history"): api_history,
    ("GET", "/history/search"): api_history_search,
    ("GET", "/sitemap"): api_sitemap,
    ("GET", "/scope"): api_scope_check,
    ("POST", "/scope"): api_scope_update,
    ("POST", "/send"): api_send,
    ("POST", "/replay_batch"): api_replay_batch,
    ("POST", "/repeater"): api_repeater,
    ("POST", "/intruder"): api_intruder,
    ("POST", "/scan/active"): api_scan_active,
    ("POST", "/scan/passive"): api_scan_passive,
    ("GET", "/scan/status"): api_scan_status,
    ("POST", "/scan/cancel"): api_scan_cancel,
    ("GET", "/issues"): api_issues,
    ("POST", "/issues"): api_issue_add,
    ("POST", "/collab/payload"): api_collab_payload,
    ("GET", "/collab/interactions"): api_collab_interactions,
    ("GET", "/cookies"): api_cookies_get,
    ("POST", "/cookies"): api_cookies_set,
    ("POST", "/annotate"): api_annotate,
    ("GET", "/log"): api_log,
    ("GET", "/audit"): api_audit,
    ("POST", "/intercept/config"): api_intercept_config,
    ("GET", "/intercept/pending"): api_intercept_pending,
    ("POST", "/intercept/resolve"): api_intercept_resolve,
}
PREFIX_ROUTES = {("GET", "/history/"): api_history_item, ("GET", "/log/"): api_log_item}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, fmt, *args):
        pass

    def _reply(self, status, obj):
        data = json.dumps(obj)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _guard(self):
        # custom header forces a CORS preflight (blocks web pages); Host check blocks DNS rebinding
        host = (self.headers.get("Host") or "").split(":")[0]
        if host not in ("127.0.0.1", "localhost"):
            raise ApiError(403, "bad Host header")
        if self.headers.get("X-Burp-MCP") != "1":
            raise ApiError(403, "missing X-Burp-MCP header")
        if TOKEN and self.headers.get("X-Burp-MCP-Token") != TOKEN:
            raise ApiError(403, "bad token")

    def _dispatch(self, method):
        try:
            self._guard()
            u = urlparse(self.path)
            q = parse_qs(u.query)
            path = u.path.rstrip("/")
            body = {}
            if method == "POST":
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or "{}")
            fn, arg = ROUTES.get((method, path)), None
            if fn is None:
                for (m, prefix), f in PREFIX_ROUTES.items():
                    if m == method and path.startswith(prefix):
                        fn, arg = f, path[len(prefix):]
                        break
            if fn is None:
                raise ApiError(404, "unknown endpoint")
            self._reply(200, fn(q, body, arg))
        except ApiError as e:
            self._reply(e.status, {"error": e.message})
        except Exception as e:
            self._reply(500, {"error": "%s: %s" % (e.__class__.__name__, e)})

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")


class Server(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# ----------------------------------------------------------------------------
# The extension
# ----------------------------------------------------------------------------
class BurpExtender(IBurpExtender, IExtensionStateListener, IHttpListener, IProxyListener):
    def registerExtenderCallbacks(self, callbacks):
        global EXT
        EXT = self
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.log = collections.deque(maxlen=LOG_MAX)
        self.log_lock = threading.Lock()
        self.log_seq = 0
        self.audit_log = collections.deque(maxlen=500)
        self.scans, self.scan_seq = {}, 0
        self.collab = None
        self.intercept = {"enabled": False, "rules": [], "timeout": INTERCEPT_TIMEOUT}
        self.pending, self.pend_seq = {}, 0
        self.pend_lock = threading.Lock()
        callbacks.setExtensionName("MCP Bridge")
        callbacks.registerExtensionStateListener(self)
        callbacks.registerHttpListener(self)
        callbacks.registerProxyListener(self)
        try:
            self.server = Server((HOST, PORT), Handler)
        except Exception as e:
            callbacks.printError("MCP Bridge: cannot bind %s:%d: %s" % (HOST, PORT, e))
            return
        t = threading.Thread(target=self.server.serve_forever)
        t.setDaemon(True)
        t.start()
        callbacks.printOutput("MCP Bridge listening on http://%s:%d" % (HOST, PORT))

    def extensionUnloaded(self):
        with self.pend_lock:
            for p in self.pending.values():
                p["decision"] = {"action": "forward"}
                p["event"].set()
        srv = getattr(self, "server", None)
        if srv is not None:
            srv.shutdown()
            srv.server_close()

    # all-tools logger -------------------------------------------------------
    def processHttpMessage(self, toolFlag, isRequest, info):
        if isRequest:
            return
        try:
            tool = TOOL_NAMES.get(toolFlag, str(toolFlag))
            if tool == "proxy" and not LOG_PROXY:
                return
            req, resp = info.getRequest(), info.getResponse()
            svc = info.getHttpService()
            ar = self.helpers.analyzeRequest(info)
            status = self.helpers.analyzeResponse(resp).getStatusCode() if resp is not None else None
            self.log_seq += 1
            entry = {
                "seq": self.log_seq, "tool": tool, "time": time.strftime("%H:%M:%S"),
                "method": ar.getMethod(), "url": ar.getUrl().toString(),
                "host": svc.getHost(), "port": svc.getPort(), "https": svc.getProtocol() == "https",
                "status": status, "response_length": len(resp) if resp is not None else None,
                "request": req[:LOG_BODY_MAX], "response": resp[:LOG_BODY_MAX] if resp is not None else None,
            }
            with self.log_lock:
                self.log.append(entry)
        except Exception as e:
            self.callbacks.printError("MCP Bridge logger: %s" % e)

    # emulated intercept -----------------------------------------------------
    def processProxyMessage(self, isRequest, msg):
        st = self.intercept
        if not st["enabled"] or not ALLOW_INTERCEPT:
            return
        try:
            info = msg.getMessageInfo()
            ar = self.helpers.analyzeRequest(info)
            url, method = ar.getUrl().toString(), ar.getMethod()
            host = info.getHttpService().getHost()
            if not any(rule_matches(r, isRequest, method, url, host) for r in st["rules"]):
                return
        except Exception as e:
            self.callbacks.printError("MCP Bridge intercept match: %s" % e)
            return
        with self.pend_lock:
            self.pend_seq += 1
            pid = self.pend_seq
            p = {"direction": "request" if isRequest else "response", "method": method, "url": url,
                 "request": info.getRequest(), "response": info.getResponse(),
                 "event": threading.Event(), "decision": None,
                 "deadline": time.time() + st["timeout"]}
            self.pending[pid] = p
        msg.setInterceptAction(msg.ACTION_DONT_INTERCEPT)  # we hold it ourselves
        p["event"].wait(st["timeout"])
        with self.pend_lock:
            self.pending.pop(pid, None)
        d = p["decision"] or {"action": "forward"}
        if d["action"] == "drop":
            msg.setInterceptAction(msg.ACTION_DROP)
            return
        if isRequest and d.get("request"):
            info.setRequest(to_bytes(normalize_raw(d["request"])))
        elif not isRequest and d.get("response"):
            info.setResponse(to_bytes(d["response"]))
