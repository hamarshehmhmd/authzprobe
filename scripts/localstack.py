"""A small local Supabase look-alike for tests and the demo.

Real Postgres + real PostgREST, behind a tiny gateway that behaves like
Supabase's on the parts authzprobe uses:
  /rest/v1/*          -> PostgREST (apikey required; OpenAPI root needs service_role, like Supabase since 2026-04)
  /auth/v1/admin/users, /auth/v1/token?grant_type=password   (in-memory GoTrue stand-in)
  /storage/v1/bucket, /storage/v1/object/list/<bucket>       (in-memory Storage stand-in)

Usage:
  python scripts/localstack.py up [--schema examples/vibeapp/schema.sql]   # runs until Ctrl-C
Needs Postgres server binaries (PG_BIN or on PATH) and a postgrest binary (POSTGREST or on PATH).
"""
import argparse
import glob
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src"))
from authzprobe.jwtutil import mint, verify  # noqa: E402

JWT_SECRET = "super-secret-jwt-token-with-at-least-32-characters-long"


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def find_pg_bin():
    cands = [os.environ.get("PG_BIN", "")]
    if shutil.which("pg_ctl"):
        cands.append(os.path.dirname(shutil.which("pg_ctl")))
    cands += sorted(glob.glob("/usr/lib/postgresql/*/bin"), reverse=True)
    cands += ["/workspace/tools/pg17/bin", "/opt/homebrew/bin", "/usr/local/bin"]
    for c in cands:
        if c and os.path.exists(os.path.join(c, "initdb")) and os.path.exists(os.path.join(c, "postgres")):
            return c
    return None


def find_postgrest():
    for c in (os.environ.get("POSTGREST"), shutil.which("postgrest"), "/workspace/tools/postgrest"):
        if c and os.path.exists(c):
            return c
    return None


class Stack:
    def __init__(self, schema_files, gateway_port=None):
        self.pg_bin = find_pg_bin()
        self.postgrest_bin = find_postgrest()
        if not self.pg_bin or not self.postgrest_bin:
            raise RuntimeError("need Postgres server binaries (PG_BIN) and postgrest (POSTGREST)")
        self.schema_files = schema_files
        self.dir = tempfile.mkdtemp(prefix="authzprobe-stack-")
        self.pg_port = free_port()
        self.rest_port = free_port()
        self.port = gateway_port or free_port()
        self.procs = []
        self.server = None
        self.anon_key = mint(JWT_SECRET, {"role": "anon", "iss": "supabase-demo"}, ttl=10 * 365 * 86400)
        self.service_key = mint(JWT_SECRET, {"role": "service_role", "iss": "supabase-demo"}, ttl=10 * 365 * 86400)
        self.users = {}
        self.buckets = {
            "avatars": {"public": True, "list": "anon", "objects": {}},
            "documents": {"public": False, "list": "authenticated", "objects": {
                "11111111-1111-4111-8111-111111111111": ["passport.jpg", "lease.pdf"],
                "22222222-2222-4222-8222-222222222222": ["id-card.png"]}},
            "receipts": {"public": False, "list": "owner", "objects": {
                "11111111-1111-4111-8111-111111111111": ["r1.pdf"]}},
        }

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    @property
    def rest_url(self):
        return f"http://127.0.0.1:{self.rest_port}"

    def psql(self, sql=None, file=None):
        cmd = [os.path.join(self.pg_bin, "psql"), "-h", "127.0.0.1", "-p", str(self.pg_port), "-U", "postgres",
               "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-q"]
        cmd += ["-f", file] if file else ["-c", sql]
        if not os.path.exists(cmd[0]):
            cmd[0] = shutil.which("psql")
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)

    def start(self):
        data = os.path.join(self.dir, "data")
        subprocess.run([os.path.join(self.pg_bin, "initdb"), "-D", data, "-U", "postgres", "-A", "trust",
                        "--no-sync", "-E", "UTF8"], check=True, stdout=subprocess.DEVNULL)
        log = open(os.path.join(self.dir, "pg.log"), "w")
        self.procs.append(subprocess.Popen([os.path.join(self.pg_bin, "postgres"), "-D", data, "-p", str(self.pg_port),
                                            "-c", "listen_addresses=127.0.0.1", "-c", "fsync=off",
                                            "-k", self.dir], stdout=log, stderr=log))
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", self.pg_port), 0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        time.sleep(0.3)
        self.psql(file=os.path.join(ROOT, "examples", "vibeapp", "supabase_roles.sql"))
        for f in self.schema_files:
            self.psql(file=f)
        self._start_postgrest()
        self._start_gateway()
        return self

    def _start_postgrest(self):
        conf = os.path.join(self.dir, "postgrest.conf")
        with open(conf, "w") as fh:
            fh.write(f'db-uri = "postgres://authenticator:authzprobe-local@127.0.0.1:{self.pg_port}/postgres"\n'
                     'db-schemas = "public"\ndb-anon-role = "anon"\n'
                     f'jwt-secret = "{JWT_SECRET}"\nserver-host = "127.0.0.1"\nserver-port = {self.rest_port}\n'
                     'db-channel-enabled = true\n')
        log = open(os.path.join(self.dir, "postgrest.log"), "w")
        self.procs.append(subprocess.Popen([self.postgrest_bin, conf], stdout=log, stderr=log))
        for _ in range(100):
            try:
                urllib.request.urlopen(self.rest_url + "/", timeout=1)
                return
            except urllib.error.HTTPError:
                return
            except Exception:
                time.sleep(0.1)
        raise RuntimeError("postgrest did not start: " + open(os.path.join(self.dir, "postgrest.log")).read())

    def reload_schema(self):
        self.psql("notify pgrst, 'reload schema'")
        time.sleep(0.6)

    def _start_gateway(self):
        stack = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, status, body=b"", headers=None):
                if isinstance(body, (dict, list)):
                    body = json.dumps(body).encode()
                self.send_response(status)
                hs = {"Content-Type": "application/json"}
                hs.update(headers or {})
                for k, v in hs.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _body(self):
                n = int(self.headers.get("Content-Length") or 0)
                return self.rfile.read(n) if n else b""

            def _claims(self):
                key = self.headers.get("apikey")
                if not key or not verify(JWT_SECRET, key):
                    return None, None
                auth = self.headers.get("Authorization", "")
                tok = auth[7:] if auth.startswith("Bearer ") else key
                return verify(JWT_SECRET, key), verify(JWT_SECRET, tok)

            def _route(self, method):
                path, _, query = self.path.partition("?")
                if method == "GET" and (path == "/" or path.startswith("/assets/")):
                    page = stack.site_files().get(path)
                    if page is None:
                        return self._send(404, b"not found", {"Content-Type": "text/plain"})
                    ctype = "text/html" if path == "/" else "application/javascript"
                    return self._send(200, page.encode(), {"Content-Type": ctype})
                body = self._body()
                keyc, claims = self._claims()
                if keyc is None:
                    return self._send(401, {"message": "Invalid API key"})
                if claims is None:
                    return self._send(401, {"message": "invalid JWT"})
                role = claims.get("role")
                if path.startswith("/rest/v1"):
                    sub = path[len("/rest/v1"):] or "/"
                    if sub == "/" and keyc.get("role") != "service_role":
                        return self._send(403, {"message": "Access to schema is forbidden",
                                                "hint": "Accessing the schema via the Data API is only allowed "
                                                        "using a secret API key."})
                    url = stack.rest_url + sub + ("?" + query if query else "")
                    hdrs = {k: v for k, v in self.headers.items()
                            if k.lower() in ("accept", "content-type", "prefer", "range")}
                    tok = self.headers.get("Authorization", "")[7:] or self.headers.get("apikey")
                    hdrs["Authorization"] = "Bearer " + tok
                    req = urllib.request.Request(url, data=body or None, headers=hdrs, method=method)
                    try:
                        with urllib.request.urlopen(req, timeout=30) as r:
                            st, rh, rb = r.status, r.headers, r.read()
                    except urllib.error.HTTPError as e:
                        st, rh, rb = e.code, e.headers, e.read()
                    keep = {k: v for k, v in rh.items() if k.lower() in ("content-type", "content-range")}
                    return self._send(st, rb, keep)
                if path == "/auth/v1/admin/users" and method == "POST":
                    if role != "service_role":
                        return self._send(403, {"msg": "User not allowed"})
                    d = json.loads(body or b"{}")
                    uid = str(uuid.uuid4())
                    stack.users[uid] = d
                    return self._send(200, {"id": uid, "email": d.get("email"), "aud": "authenticated"})
                if path.startswith("/auth/v1/admin/users/") and method == "DELETE":
                    if role != "service_role":
                        return self._send(403, {"msg": "User not allowed"})
                    stack.users.pop(path.rsplit("/", 1)[-1], None)
                    return self._send(200, {})
                if path == "/auth/v1/token" and "grant_type=password" in query:
                    d = json.loads(body or b"{}")
                    for uid, u in stack.users.items():
                        if u.get("email") == d.get("email") and u.get("password") == d.get("password"):
                            tok = mint(JWT_SECRET, {"sub": uid, "role": "authenticated", "aud": "authenticated",
                                                    "email": u.get("email")})
                            return self._send(200, {"access_token": tok, "token_type": "bearer",
                                                    "user": {"id": uid}})
                    return self._send(400, {"error": "invalid_grant", "error_description": "Invalid login credentials"})
                if path == "/storage/v1/bucket" and method == "GET":
                    out = [{"id": k, "name": k, "public": v["public"]} for k, v in stack.buckets.items()
                           if role == "service_role" or v["public"]]
                    return self._send(200, out)
                if path.startswith("/storage/v1/object/list/") and method == "POST":
                    b = stack.buckets.get(urllib.parse.unquote(path.rsplit("/", 1)[-1]))
                    if not b:
                        return self._send(400, {"error": "Bucket not found"})
                    sub_id = claims.get("sub")
                    rule = b["list"]
                    if role == "service_role" or rule == "anon" or (rule == "authenticated" and role == "authenticated"):
                        names = list(b["objects"])
                    elif rule == "owner" and sub_id:
                        names = [n for n in b["objects"] if n == sub_id]
                    else:
                        names = []
                    return self._send(200, [{"name": n, "id": None} for n in names])
                return self._send(404, {"message": "not found"})

            def do_GET(self):
                self._route("GET")

            def do_HEAD(self):
                self._route("HEAD")

            def do_POST(self):
                self._route("POST")

            def do_PATCH(self):
                self._route("PATCH")

            def do_DELETE(self):
                self._route("DELETE")

        self.server = ThreadingHTTPServer(("127.0.0.1", self.port), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def site_files(self):
        """A tiny Vite-style build of the example app, like what Lovable/Bolt deploy."""
        main = (
            'import{c as createClient}from"./vendor-3f9a1c.js";'
            f'const sb=createClient("{self.url}","{self.anon_key}");'
            'export async function load(){const p=await sb.from("profiles").select("*");'
            'const m=await sb.from("messages").select("*").eq("user_id",u);'
            'await sb.from("orders").insert({user_id:u,amount:1});'
            'const s=await sb.rpc("get_user_stats");'
            'const f=await sb.storage.from("documents").upload(u+"/id.png",file);'
            'const a=sb.storage.from("avatars").getPublicUrl(u);return [p,m,s,f,a]}'
            'import("./Settings-8d2e0b.js");'
        )
        return {
            "/": '<!doctype html><html><head><title>Circle - community app</title>'
                 '<script type="module" crossorigin src="/assets/index-a1b2c3.js"></script></head>'
                 '<body><div id="root"></div></body></html>',
            "/assets/index-a1b2c3.js": main,
            "/assets/vendor-3f9a1c.js": "export function c(u,k){return {from(){},rpc(){},storage:{from(){}}}}",
            "/assets/Settings-8d2e0b.js": 'export const n=async(sb)=>sb.from("notes").select("id,title");',
        }

    def stop(self):
        if self.server:
            self.server.shutdown()
        for p in reversed(self.procs):
            p.terminate()
            try:
                p.wait(10)
            except Exception:
                p.kill()
        shutil.rmtree(self.dir, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["up"])
    ap.add_argument("--schema", action="append")
    ap.add_argument("--port", type=int, default=54321)
    ap.add_argument("--env-file")
    a = ap.parse_args()
    schemas = a.schema or [os.path.join(ROOT, "examples", "vibeapp", "schema.sql")]
    st = Stack(schemas, gateway_port=a.port).start()
    env = (f"SUPABASE_URL={st.url}\nSUPABASE_ANON_KEY={st.anon_key}\nSUPABASE_SERVICE_ROLE_KEY={st.service_key}\n"
           f"SUPABASE_JWT_SECRET={JWT_SECRET}\nPG_PORT={st.pg_port}\nREST_URL={st.rest_url}\n")
    if a.env_file:
        with open(a.env_file, "w") as fh:
            fh.write(env)
    print(env, flush=True)
    print("ready", flush=True)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        st.stop()


if __name__ == "__main__":
    main()
