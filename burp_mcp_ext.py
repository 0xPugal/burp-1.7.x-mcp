# -*- coding: utf-8 -*-
# Burp Suite 1.7.x extension (Jython 2.7): exposes proxy history and request
# sending over a localhost-only HTTP/JSON API. mcp_server.py wraps it as MCP.
#
# Endpoints (all JSON, bound to 127.0.0.1, require header "X-Burp-MCP: 1"):
#   GET  /ping
#   GET  /history?offset=0&limit=50&host=&method=&status=&contains=&in_scope=&newest_first=1
#   GET  /history/<id>?max_chars=20000
#   POST /send      {request | method,url,headers,body | history_id, ...}
#   POST /repeater  same body as /send, plus optional "caption"

from burp import IBurpExtender, IExtensionStateListener
from java.lang import String, Runnable
from java.awt import Container, Frame
from javax.swing import JButton, JTabbedPane, SwingUtilities
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from SocketServer import ThreadingMixIn
from urlparse import urlparse, parse_qs
import json
import re
import threading
import time

HOST = "127.0.0.1"
PORT = 8765
TOKEN = ""  # optional: if set, clients must send it as header X-Burp-MCP-Token
DEFAULT_MAX_CHARS = 20000
LATIN1 = "ISO-8859-1"

EXT = None


def to_text(byte_array):
    if byte_array is None:
        return ""
    return unicode(String(byte_array, LATIN1))


def to_bytes(text):
    return String(text).getBytes(LATIN1)


def clip(text, max_chars):
    if max_chars and len(text) > max_chars:
        return text[:max_chars] + "\n...[truncated %d of %d chars]" % (max_chars, len(text))
    return text


class ApiError(Exception):
    def __init__(self, status, message):
        Exception.__init__(self, message)
        self.status = status
        self.message = message


def normalize_raw(raw):
    """CRLF-normalise the head and fix Content-Length to match the body."""
    m = re.search(r"\r?\n\r?\n", raw)
    if m:
        head, body = raw[:m.start()], raw[m.end():]
    else:
        head, body = raw, ""
    head = re.sub(r"\r?\n", "\r\n", head)
    lines = head.split("\r\n")
    lines = [l for l in lines if not re.match(r"(?i)content-length\s*:", l)]
    if body:
        lines.append("Content-Length: %d" % len(to_bytes(body)))
    return "\r\n".join(lines) + "\r\n\r\n" + body


def build_from_parts(spec):
    url = spec.get("url")
    if not url:
        raise ApiError(400, "need 'request', 'history_id', or 'method'+'url'")
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
    body = spec.get("body") or ""
    names = [k.lower() for k in headers]
    lines = ["%s %s HTTP/1.1" % (method, path)]
    if "host" not in names:
        default = (https and port == 443) or (not https and port == 80)
        lines.append("Host: %s" % (u.hostname if default else "%s:%d" % (u.hostname, port)))
    for k, v in headers.items():
        lines.append("%s: %s" % (k, v))
    raw = "\r\n".join(lines) + "\r\n\r\n" + body
    return u.hostname, port, https, normalize_raw(raw)


def resolve_target(spec):
    """Return (host, port, https, raw_request_text) from any accepted input shape."""
    callbacks, helpers = EXT.callbacks, EXT.helpers
    if spec.get("history_id") is not None:
        hist = callbacks.getProxyHistory()
        idx = int(spec["history_id"])
        if idx < 0 or idx >= len(hist):
            raise ApiError(404, "no history item %d" % idx)
        svc = hist[idx].getHttpService()
        host, port, https = svc.getHost(), svc.getPort(), svc.getProtocol() == "https"
        raw = spec.get("request")
        if raw is None:
            raw = to_text(hist[idx].getRequest())
        else:
            raw = normalize_raw(raw)
        return host, port, https, raw

    if spec.get("request"):
        raw = normalize_raw(spec["request"])
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
        return host, int(port), bool(https), raw

    return build_from_parts(spec)


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
    return out


def api_history(q):
    callbacks = EXT.callbacks
    offset = int(q.get("offset", ["0"])[0])
    limit = min(int(q.get("limit", ["50"])[0]), 500)
    host = q.get("host", [""])[0].lower()
    method = q.get("method", [""])[0].upper()
    status = q.get("status", [""])[0]
    contains = q.get("contains", [""])[0].lower()
    in_scope = q.get("in_scope", [""])[0] in ("1", "true")
    newest_first = q.get("newest_first", ["1"])[0] in ("1", "true")

    hist = callbacks.getProxyHistory()
    total = len(hist)
    order = range(total - 1, -1, -1) if newest_first else range(total)
    matched = []
    skipped = 0
    for i in order:
        s = summarize(i, hist[i])
        if host and host not in s["host"].lower():
            continue
        if method and s["method"] != method:
            continue
        if status and str(s["status"]) != status:
            continue
        if contains and contains not in s["url"].lower():
            continue
        if in_scope and not callbacks.isInScope(EXT.helpers.analyzeRequest(hist[i]).getUrl()):
            continue
        if skipped < offset:
            skipped += 1
            continue
        matched.append(s)
        if len(matched) >= limit:
            break
    return {"total_history": total, "returned": len(matched), "items": matched}


def api_history_item(idx, q):
    hist = EXT.callbacks.getProxyHistory()
    if idx < 0 or idx >= len(hist):
        raise ApiError(404, "no history item %d" % idx)
    max_chars = int(q.get("max_chars", [str(DEFAULT_MAX_CHARS)])[0])
    item = hist[idx]
    out = summarize(idx, item)
    out["request"] = clip(to_text(item.getRequest()), max_chars)
    resp = item.getResponse()
    out["response"] = clip(to_text(resp), max_chars) if resp is not None else None
    comment = item.getComment()
    if comment:
        out["comment"] = comment
    return out


def api_send(spec):
    host, port, https, raw = resolve_target(spec)
    max_chars = int(spec.get("max_chars", DEFAULT_MAX_CHARS))
    t0 = time.time()
    resp = EXT.callbacks.makeHttpRequest(host, port, https, to_bytes(raw))
    elapsed = int((time.time() - t0) * 1000)
    out = {
        "host": host, "port": port, "https": https,
        "elapsed_ms": elapsed,
        "request": clip(raw, max_chars),
    }
    if resp is None or len(resp) == 0:
        out["response"] = None
        out["error"] = "no response (connection failed or timed out)"
        return out
    ar = EXT.helpers.analyzeResponse(resp)
    out["status"] = ar.getStatusCode()
    out["response_length"] = len(resp)
    out["response"] = clip(to_text(resp), max_chars)
    return out


def _walk(comp, kind, out):
    if isinstance(comp, kind):
        out.append(comp)
    if isinstance(comp, Container):
        for c in comp.getComponents():
            _walk(c, kind, out)


def _click_go(caption):
    """Runs on the Swing EDT. Click Go in the Repeater tab titled `caption`.
    Returns True if clicked, False if the tab/button is not there (yet)."""
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
                        idx = i  # keep the last match: newest tab
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
    # the tab is created asynchronously by Burp, so retry for ~3 seconds
    for _ in range(attempts):
        task = _EdtTask(caption)
        SwingUtilities.invokeAndWait(task)
        if task.result:
            return True
        time.sleep(delay)
    return False


def api_repeater(spec):
    host, port, https, raw = resolve_target(spec)
    send = bool(spec.get("send"))
    caption = spec.get("caption") or "MCP"
    if send:
        # make the caption unique so we click Go in the tab we just created
        caption = "%s-%d" % (caption, int(time.time() * 1000) % 100000)
    EXT.callbacks.sendToRepeater(host, port, https, to_bytes(raw), caption)
    out = {"ok": True, "host": host, "port": port, "https": https,
           "caption": caption, "sent": False}
    if send:
        out["sent"] = click_repeater_go(caption)
        if not out["sent"]:
            out["warning"] = ("tab created but the Go button could not be found/clicked; "
                              "press Go manually in the Repeater tab")
    return out


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
        # custom header forces a CORS preflight, so web pages cannot call us;
        # Host check blocks DNS rebinding.
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
            if method == "GET" and path == "/ping":
                result = {"ok": True, "burp": EXT.callbacks.getBurpVersion()[1:3],
                          "history_size": len(EXT.callbacks.getProxyHistory())}
            elif method == "GET" and path == "/history":
                result = api_history(q)
            elif method == "GET" and path.startswith("/history/"):
                result = api_history_item(int(path.split("/")[2]), q)
            elif method == "POST" and path == "/send":
                result = api_send(body)
            elif method == "POST" and path == "/repeater":
                result = api_repeater(body)
            else:
                raise ApiError(404, "unknown endpoint")
            self._reply(200, result)
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


class BurpExtender(IBurpExtender, IExtensionStateListener):
    def registerExtenderCallbacks(self, callbacks):
        global EXT
        EXT = self
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("MCP Bridge")
        callbacks.registerExtensionStateListener(self)
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
        srv = getattr(self, "server", None)
        if srv is not None:
            srv.shutdown()
            srv.server_close()
