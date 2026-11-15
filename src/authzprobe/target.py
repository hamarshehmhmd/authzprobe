"""A Supabase (or plain PostgREST) project and the identities we test as."""
import secrets
import urllib.parse
import uuid

from . import http
from .jwtutil import is_jwt, key_role, mint


class Identity:
    def __init__(self, name, token=None, user_id=None, email=None, kind="user"):
        self.name = name          # "anon", "user A", "user B", "service"
        self.token = token        # bearer JWT (None = API key only)
        self.user_id = user_id
        self.email = email
        self.kind = kind          # anon | user | service
        self.admin_created = False


class TargetError(RuntimeError):
    pass


class Target:
    """Talks to /rest/v1, /auth/v1 and /storage/v1 of one project.

    rest_url can point at a bare PostgREST server (no gateway) for local tests;
    then auth and storage are unavailable and test users are minted with the
    JWT secret.
    """

    def __init__(self, url, anon_key=None, service_key=None, jwt_secret=None, rest_url=None,
                 request=None, jwt_aud="authenticated"):
        self.url = (url or "").rstrip("/")
        self.rest = (rest_url or (self.url + "/rest/v1")).rstrip("/")
        self.jwt_secret = jwt_secret
        self.jwt_aud = jwt_aud
        self._request = request or http.request
        if not anon_key and jwt_secret:
            anon_key = mint(jwt_secret, {"role": "anon"}, ttl=7200)
        if not service_key and jwt_secret:
            service_key = mint(jwt_secret, {"role": "service_role"}, ttl=7200)
        if service_key and key_role(service_key) not in ("service_role", None):
            raise TargetError("--service-key is not a service_role / sb_secret_ key")
        if anon_key and key_role(anon_key) == "service_role":
            raise TargetError("the key passed as anon key is a service_role key")
        self.anon_key = anon_key
        self.service_key = service_key
        self.anon = Identity("anon", kind="anon")
        self.service = Identity("service", kind="service") if service_key else None

    # ---- low level -------------------------------------------------------
    def headers(self, ident, extra=None):
        h = {}
        if ident.kind == "service":
            h["apikey"] = self.service_key
            if is_jwt(self.service_key):
                h["Authorization"] = "Bearer " + self.service_key
        else:
            if self.anon_key:
                h["apikey"] = self.anon_key
            if ident.token:
                h["Authorization"] = "Bearer " + ident.token
            elif self.anon_key and is_jwt(self.anon_key):
                h["Authorization"] = "Bearer " + self.anon_key
        if extra:
            h.update(extra)
        return h

    def call(self, method, url, ident, body=None, extra=None):
        return self._request(method, url, headers=self.headers(ident, extra), body=body)

    def rest_call(self, method, path, ident, params=None, body=None, prefer=None):
        url = self.rest + "/" + path.lstrip("/")
        if params:
            url += "?" + urllib.parse.urlencode(params, safe="*,.()")
        extra = {"Prefer": prefer} if prefer else None
        return self.call(method, url, ident, body=body, extra=extra)

    # ---- schema ----------------------------------------------------------
    def openapi(self, ident):
        r = self.call("GET", self.rest + "/", ident, extra={"Accept": "application/openapi+json"})
        return r

    # ---- rows ------------------------------------------------------------
    def count(self, table, ident, filters=None):
        """Return (visible_count or None, response). Uses Prefer: count=exact."""
        params = {"select": "*", "limit": "1"}
        params.update(filters or {})
        r = self.rest_call("GET", table, ident, params=params, prefer="count=exact")
        if not r.ok:
            return None, r
        cr = r.headers.get("content-range", "")
        total = cr.rsplit("/", 1)[-1] if "/" in cr else ""
        if total.isdigit():
            return int(total), r
        rows = r.json()
        return (len(rows) if isinstance(rows, list) else None), r

    def sample_columns(self, table, ident):
        r = self.rest_call("GET", table, ident, params={"select": "*", "limit": "1"})
        rows = r.json() if r.ok else None
        if isinstance(rows, list) and rows and isinstance(rows[0], dict):
            return list(rows[0].keys())
        return []

    # ---- users -----------------------------------------------------------
    def make_user(self, label, run_id):
        """Create a throwaway authenticated user. Returns Identity."""
        email = f"authzprobe+{run_id}-{label.lower().replace(' ', '')}@example.com"
        if self.service and self.url and not self.jwt_secret_preferred():
            password = secrets.token_urlsafe(24) + "aA1!"
            r = self.call("POST", self.url + "/auth/v1/admin/users", self.service,
                          body={"email": email, "password": password, "email_confirm": True,
                                "user_metadata": {"authzprobe": run_id}})
            if r.ok:
                user = r.json() or {}
                uid = user.get("id") or (user.get("user") or {}).get("id")
                t = self._request("POST", self.url + "/auth/v1/token?grant_type=password",
                                  headers={"apikey": self.anon_key or ""},
                                  body={"email": email, "password": password})
                tok = (t.json() or {}).get("access_token") if t.ok else None
                ident = Identity(label, token=tok, user_id=uid, email=email)
                ident.admin_created = True
                if not tok:
                    self.delete_user(ident)
                    raise TargetError(f"created {email} but password sign-in failed: HTTP {t.status} "
                                      f"{t.error_message()}")
                return ident
            if not self.jwt_secret:
                raise TargetError(f"could not create a test user via /auth/v1/admin/users: HTTP {r.status} "
                                  f"{r.error_message()}")
        if self.jwt_secret:
            uid = str(uuid.uuid4())
            tok = mint(self.jwt_secret, {"sub": uid, "role": "authenticated", "aud": self.jwt_aud,
                                         "email": email, "is_anonymous": False})
            return Identity(label, token=tok, user_id=uid, email=email)
        raise TargetError("need --service-key (creates real throwaway users) or --jwt-secret "
                          "(mints test-user tokens) or two --user-token values")

    def jwt_secret_preferred(self):
        # With a bare PostgREST (no gateway) there is no auth server to call.
        return bool(self.jwt_secret) and self.rest != self.url + "/rest/v1"

    def delete_user(self, ident):
        if ident.admin_created and ident.user_id and self.service:
            self.call("DELETE", f"{self.url}/auth/v1/admin/users/{ident.user_id}", self.service)

    # ---- storage ---------------------------------------------------------
    def buckets(self, ident):
        return self.call("GET", self.url + "/storage/v1/bucket", ident)

    def list_objects(self, bucket, ident, prefix=""):
        return self.call("POST", f"{self.url}/storage/v1/object/list/{urllib.parse.quote(bucket)}", ident,
                         body={"prefix": prefix, "limit": 20, "offset": 0})
