"""Minimal JSON HTTP client on urllib."""
import json
import urllib.error
import urllib.request

USER_AGENT = "authzprobe/0.1 (+https://github.com/hamarshehmhmd/authzprobe)"


class Response:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.body = body

    @property
    def ok(self):
        return 200 <= self.status < 300

    def json(self):
        if not self.body:
            return None
        try:
            return json.loads(self.body)
        except ValueError:
            return None

    @property
    def text(self):
        return self.body.decode("utf-8", "replace") if isinstance(self.body, bytes) else (self.body or "")

    def error_message(self):
        data = self.json()
        if isinstance(data, dict):
            for k in ("message", "msg", "error_description", "error"):
                if data.get(k):
                    code = data.get("code")
                    return f"{data[k]}" + (f" ({code})" if code else "")
        return self.text[:200]

    def __repr__(self):
        return f"<Response {self.status}>"


def request(method, url, headers=None, body=None, timeout=30):
    data = None
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    hdrs.update(headers or {})
    if body is not None:
        data = json.dumps(body).encode() if not isinstance(body, (bytes, str)) else (
            body.encode() if isinstance(body, str) else body)
        hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return Response(r.status, dict(r.headers), r.read())
    except urllib.error.HTTPError as e:
        return Response(e.code, dict(e.headers or {}), e.read() if e.fp else b"")
