"""An in-memory Supabase-ish backend for unit tests (no Postgres needed).

Policies are Python callables: policy(role, uid, row) -> bool, per command.
"""
import json
import urllib.parse
import uuid

from authzprobe.http import Response
from authzprobe.jwtutil import mint, verify

SECRET = "unit-test-secret-unit-test-secret-1234"
ANON = mint(SECRET, {"role": "anon"})
SERVICE = mint(SECRET, {"role": "service_role"})


def owner(col):
    return lambda role, uid, row: uid is not None and row.get(col) == uid


def anyone(role, uid, row):
    return True


def authed(role, uid, row):
    return role == "authenticated"


def nobody(role, uid, row):
    return False


class Table:
    def __init__(self, name, columns, rows=None, select=nobody, insert=nobody, update=nobody, delete=nobody,
                 pk="id", pk_identity=True):
        self.name, self.columns, self.rows = name, columns, list(rows or [])
        self.pol = {"select": select, "insert": insert, "update": update, "delete": delete}
        self.pk, self.pk_identity = pk, pk_identity
        self.seq = 100


class FakeBackend:
    def __init__(self, tables, buckets=None, openapi_for_anon=False, admin=True):
        self.tables = {t.name: t for t in tables}
        self.buckets = buckets or {}
        self.openapi_for_anon = openapi_for_anon
        self.admin = admin
        self.users = {}
        self.calls = []

    # -- openapi ----------------------------------------------------------
    def spec(self):
        paths, defs = {"/": {}}, {}
        for t in self.tables.values():
            paths["/" + t.name] = {"get": {}, "post": {}, "patch": {}, "delete": {}}
            props, req = {}, []
            for c, fmt in t.columns.items():
                p = {"format": fmt, "type": "string" if fmt in ("uuid", "text") else "integer"}
                if c == t.pk:
                    p["description"] = "Note:\nThis is a Primary Key.<pk/>"
                    if t.pk_identity:
                        req.append(c)  # identity columns are NOT NULL without default, like PostgREST shows
                        continue
                req.append(c)
                props[c] = p
            for c, fmt in t.columns.items():
                if c == t.pk:
                    props[c] = {"format": fmt, "type": "integer" if fmt != "uuid" else "string",
                                "description": "Note:\nThis is a Primary Key.<pk/>"}
            defs[t.name] = {"properties": props, "required": req}
        paths["/rpc/do_thing"] = {"post": {}}
        return {"swagger": "2.0", "paths": paths, "definitions": defs}

    # -- transport ----------------------------------------------------------
    def __call__(self, method, url, headers=None, body=None, timeout=30):
        headers = headers or {}
        self.calls.append((method, url))
        u = urllib.parse.urlsplit(url)
        q = urllib.parse.parse_qs(u.query)
        key = headers.get("apikey")
        if not key or not verify(SECRET, key):
            return self._r(401, {"message": "Invalid API key"})
        auth = headers.get("Authorization", "")
        claims = verify(SECRET, auth[7:]) if auth.startswith("Bearer ") else verify(SECRET, key)
        if claims is None:
            return self._r(401, {"message": "JWT invalid"})
        role, uid = claims.get("role"), claims.get("sub")
        data = json.loads(body) if isinstance(body, (bytes, str)) and body else body
        path = u.path
        if path == "/rest/v1/":
            if role == "service_role" or self.openapi_for_anon:
                return self._r(200, self.spec())
            return self._r(403, {"message": "Access to schema is forbidden"})
        if path.startswith("/rest/v1/"):
            return self._rest(method, path[9:], q, headers, data, role, uid)
        if path == "/auth/v1/admin/users":
            if not self.admin:
                return self._r(404, {"message": "no auth"})
            if role != "service_role":
                return self._r(403, {"msg": "not allowed"})
            i = str(uuid.uuid4())
            self.users[i] = data
            return self._r(200, {"id": i, "email": data["email"]})
        if path.startswith("/auth/v1/admin/users/") and method == "DELETE":
            self.users.pop(path.rsplit("/", 1)[-1], None)
            return self._r(200, {})
        if path == "/auth/v1/token":
            for i, d in self.users.items():
                if d["email"] == data["email"] and d["password"] == data["password"]:
                    return self._r(200, {"access_token": mint(SECRET, {"sub": i, "role": "authenticated"})})
            return self._r(400, {"error": "invalid_grant"})
        if path == "/storage/v1/bucket":
            return self._r(200, [{"id": k, "public": v["public"]} for k, v in self.buckets.items()
                                 if role == "service_role" or v["public"]])
        if path.startswith("/storage/v1/object/list/"):
            b = self.buckets[path.rsplit("/", 1)[-1]]
            ok = role == "service_role" or b.get("list") == "anon" or (b.get("list") == "authenticated" and uid)
            return self._r(200, [{"name": n} for n in b["objects"]] if ok else [])
        return self._r(404, {"message": "nope"})

    def _r(self, status, obj, headers=None):
        return Response(status, headers or {"Content-Type": "application/json"},
                        json.dumps(obj).encode() if obj is not None else b"")

    def _match(self, row, q):
        for col, vals in q.items():
            if col in ("select", "limit"):
                continue
            op, _, v = vals[0].partition(".")
            rv = row.get(col)
            rv = None if rv is None else str(rv)
            if op == "eq" and rv != v:
                return False
            if op == "neq" and rv == v:
                return False
        return True

    def _rest(self, method, name, q, headers, data, role, uid):
        t = self.tables.get(name)
        if t is None:
            return self._r(404, {"message": f"relation public.{name} does not exist", "code": "42P01"})
        svc = role == "service_role"
        allow = lambda cmd, row: svc or t.pol[cmd](role, uid, row)  # noqa: E731
        prefer = headers.get("Prefer", "")
        visible = [r for r in t.rows if allow("select", r) and self._match(r, q)]
        if method == "GET":
            lim = int(q.get("limit", ["1000"])[0])
            hdr = {"Content-Type": "application/json"}
            if "count=exact" in prefer:
                hdr["Content-Range"] = (f"0-{min(lim, len(visible)) - 1}/{len(visible)}" if visible
                                        else f"*/{len(visible)}")
            return self._r(200, visible[:lim], hdr)
        if method == "POST":
            row = dict(data)
            if t.pk_identity and t.pk in row:
                return self._r(400, {"message": f'cannot insert a non-DEFAULT value into column "{t.pk}"',
                                     "code": "428C9"})
            if not allow("insert", row):
                return self._r(401 if role == "anon" else 403,
                               {"message": "new row violates row-level security policy", "code": "42501"})
            if t.pk_identity:
                t.seq += 1
                row[t.pk] = t.seq
            t.rows.append(row)
            return self._r(201, None, {})
        if method == "PATCH":
            n = 0
            for r in t.rows:
                if self._match(r, q) and (svc or (t.pol["select"](role, uid, r) or True) and allow("update", r)):
                    r.update(data)
                    n += 1
            return self._r(204, None, {"Content-Range": f"*/{n}"})
        if method == "DELETE":
            keep, n = [], 0
            for r in t.rows:
                if self._match(r, q) and allow("delete", r):
                    n += 1
                else:
                    keep.append(r)
            t.rows = keep
            return self._r(204, None, {"Content-Range": f"*/{n}"})
        return self._r(405, {"message": "method"})
