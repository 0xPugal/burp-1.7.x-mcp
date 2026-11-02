"""Tests for the pure-logic parts of burp_mcp_ext.py and mcp_server.py.

The Burp/Java/Jython modules are stubbed so the extension imports under CPython.
Anything that needs a real Burp (helpers, callbacks, Swing) is NOT covered here.
Run:  python -m unittest discover -s tests -v
"""
import builtins
import http.server
import os
import socketserver
import sys
import types
import unittest
import urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def _stub_modules():
    builtins.unicode = str

    def mod(name, **attrs):
        m = types.ModuleType(name)
        m.__dict__.update(attrs)
        sys.modules[name] = m
        return m

    class _Obj:
        pass

    def String(x, enc=None):
        if enc is not None:
            return x.decode(enc)

        class S:
            def getBytes(self, e):
                return x.encode(e)
        return S()

    mod("burp", **{n: type(n, (), {}) for n in (
        "IBurpExtender", "IExtensionStateListener", "IHttpListener", "IProxyListener",
        "ICookie", "IScanIssue", "IHttpRequestResponse")})
    mod("java")
    mod("java.lang", String=String, Runnable=_Obj)
    mod("java.awt", Container=_Obj, Frame=_Obj)
    mod("java.net", URL=lambda s: s)
    mod("java.util", ArrayList=list, Date=_Obj)
    mod("javax")
    mod("javax.swing", JButton=_Obj, JTabbedPane=_Obj, SwingUtilities=_Obj)
    mod("jarray", array=lambda a, t=None: a)
    mod("BaseHTTPServer", BaseHTTPRequestHandler=http.server.BaseHTTPRequestHandler,
        HTTPServer=http.server.HTTPServer)
    mod("SocketServer", ThreadingMixIn=socketserver.ThreadingMixIn)
    mod("urlparse", urlparse=urllib.parse.urlparse, parse_qs=urllib.parse.parse_qs)


_stub_modules()
import burp_mcp_ext as ext  # noqa: E402
import mcp_server as srv  # noqa: E402

ext.EXT = types.SimpleNamespace(helpers=None)


class RawRequestTests(unittest.TestCase):
    def test_crlf_head_converts_and_keeps_body(self):
        out = ext.crlf_head("POST / HTTP/1.1\nHost: a\n\nline1\nline2")
        self.assertEqual(out, "POST / HTTP/1.1\r\nHost: a\r\n\r\nline1\nline2")

    def test_crlf_head_adds_blank_line(self):
        self.assertTrue(ext.crlf_head("GET / HTTP/1.1\nHost: a").endswith("\r\n\r\n"))

    def test_content_length_added_and_fixed_in_place(self):
        raw = "POST / HTTP/1.1\r\nContent-Length: 999\r\nHost: a\r\n\r\nhello"
        out = ext.normalize_raw(raw)
        self.assertIn("Content-Length: 5\r\nHost: a", out)
        self.assertEqual(out.count("Content-Length"), 1)

    def test_post_without_body_gets_zero_length(self):
        self.assertIn("Content-Length: 0", ext.normalize_raw("POST / HTTP/1.1\r\nHost: a\r\n\r\n"))

    def test_get_without_body_has_no_content_length(self):
        self.assertNotIn("Content-Length", ext.normalize_raw("GET / HTTP/1.1\r\nHost: a\r\n\r\n"))

    def test_build_from_parts(self):
        host, port, https, raw = ext.build_from_parts(
            {"method": "post", "url": "https://x.io:8443/a?b=1", "headers": {"X-A": "1"}, "body": "hi"})
        self.assertEqual((host, port, https), ("x.io", 8443, True))
        self.assertTrue(raw.startswith("POST /a?b=1 HTTP/1.1\r\nHost: x.io:8443\r\nX-A: 1"))

    def test_build_rejects_relative_url(self):
        with self.assertRaises(ext.ApiError):
            ext.build_from_parts({"url": "/relative"})


class MarkerTests(unittest.TestCase):
    def test_strip_markers(self):
        clean, offs = ext.strip_markers("GET /?a=§1§&b=§2§ HTTP/1.1")
        self.assertEqual(clean, "GET /?a=1&b=2 HTTP/1.1")
        self.assertEqual([clean[s:e] for s, e in offs], ["1", "2"])

    def test_unbalanced_markers_ignored(self):
        self.assertEqual(ext.strip_markers("a§b"), ("a§b", None))

    def test_offsets_survive_content_length_change(self):
        body = "a=§" + "0123456" + "§"
        raw = "POST / HTTP/1.1\nHost: h\nContent-Length: 1\n\n" + body
        fixed, offs = ext.prepare_with_markers(raw)
        s, e = offs[0]
        self.assertEqual(fixed[s:e], "0123456")

    def test_offsets_survive_content_length_digit_change(self):
        # 99 header digits -> 100 shifts everything after the Content-Length line
        payload = "x" * 98
        raw = "POST / HTTP/1.1\r\nContent-Length: 1\r\nHost: h\r\n\r\n=§" + payload + "§"
        fixed, offs = ext.prepare_with_markers(raw)
        s, e = offs[0]
        self.assertEqual(fixed[s:e], payload)


class ModifyTests(unittest.TestCase):
    BASE = "GET /api/users/1 HTTP/1.1\r\nHost: a\r\nCookie: s=1\r\nX-Old: 1\r\n\r\n"

    def test_headers_and_path(self):
        out = ext.apply_modify(self.BASE, {"path": "/api/users/2",
                                          "set_headers": {"Cookie": "s=2", "X-New": "z"},
                                          "remove_headers": ["x-old"]})
        self.assertIn("GET /api/users/2 HTTP/1.1", out)
        self.assertIn("Cookie: s=2", out)
        self.assertNotIn("s=1", out)
        self.assertIn("X-New: z", out)
        self.assertNotIn("X-Old", out)

    def test_method_body_replace(self):
        out = ext.apply_modify(self.BASE, {"method": "post", "body": "a=1",
                                          "replace": [{"find": "users", "replace": "admins"}]})
        self.assertTrue(out.startswith("POST /api/admins/1"))
        self.assertTrue(out.endswith("\r\n\r\na=1"))

    def test_regex_replace(self):
        out = ext.apply_modify(self.BASE, {"replace": [{"find": r"users/\d+", "replace": "users/9", "regex": True}]})
        self.assertIn("/api/users/9 ", out)


class RenderTests(unittest.TestCase):
    def test_binary_body_elided(self):
        data = b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n\x89PNG\x00\x01"
        self.assertIn("[binary body omitted: 6 bytes]", ext.render(data, 1000))

    def test_text_body_clipped(self):
        data = b"HTTP/1.1 200 OK\r\n\r\n" + b"a" * 100
        self.assertIn("truncated", ext.render(data, 40))

    def test_headers_view(self):
        out = ext.render(b"HTTP/1.1 200 OK\r\nA: b\r\n\r\nBODY", 1000, "headers")
        self.assertNotIn("BODY", out)

    def test_status_matches(self):
        self.assertTrue(ext.status_matches("4xx", 404))
        self.assertFalse(ext.status_matches("4xx", 200))
        self.assertTrue(ext.status_matches("", None))
        self.assertFalse(ext.status_matches("200", None))

    def test_rule_matches(self):
        r = {"host": "example", "direction": "request", "method": "post"}
        self.assertTrue(ext.rule_matches(r, True, "POST", "http://example.com/", "example.com"))
        self.assertFalse(ext.rule_matches(r, False, "POST", "http://example.com/", "example.com"))
        self.assertFalse(ext.rule_matches(r, True, "GET", "http://example.com/", "example.com"))


class BridgeTests(unittest.TestCase):
    def test_util_ops(self):
        self.assertEqual(srv.util("url_encode", "a b/c"), "a%20b%2Fc")
        self.assertEqual(srv.util("base64_decode", "aGk"), "hi")
        self.assertEqual(srv.util("sha256", "a")[:8], "ca978112")
        self.assertEqual(len(srv.util("random_string", length=12, charset="hex")), 12)
        with self.assertRaises(ValueError):
            srv.util("nope")

    def test_tool_list_is_valid(self):
        names = [t["name"] for t in srv.TOOLS]
        self.assertEqual(len(names), len(set(names)))
        for t in srv.TOOLS:
            self.assertEqual(t["inputSchema"]["type"], "object")
            self.assertTrue(t["description"])

    def test_every_tool_route_exists_in_extension(self):
        for name, (method, path, _d, _s) in srv.ROUTES.items():
            if "{id}" in path:
                ok = (method, path.replace("{id}", "")) in ext.PREFIX_ROUTES
            else:
                ok = (method, path) in ext.ROUTES
            self.assertTrue(ok, "%s -> %s %s has no extension route" % (name, method, path))


if __name__ == "__main__":
    unittest.main()
