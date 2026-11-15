"""The behavioral checks: what can anon, and one user, do to another user's rows?"""
import datetime
import re
import secrets
import uuid

from . import fixes
from .jwtutil import decode_unverified
from .schema import Resource, is_sensitive, parse_openapi
from .target import Identity, TargetError

SEVERITIES = ["info", "low", "medium", "high", "critical"]


class Finding:
    def __init__(self, id, severity, resource, actor, title, detail="", fix=""):
        self.id, self.severity, self.resource, self.actor = id, severity, resource, actor
        self.title, self.detail, self.fix = title, detail, fix

    def to_dict(self):
        return dict(id=self.id, severity=self.severity, resource=self.resource, actor=self.actor,
                    title=self.title, detail=self.detail, fix=self.fix)


class ScanResult:
    def __init__(self, run_id):
        self.run_id = run_id
        self.findings = []
        self.coverage = {}   # resource -> dict of check -> result string
        self.notes = []
        self.identities = []

    def add(self, *a, **k):
        f = Finding(*a, **k)
        self.findings.append(f)
        return f

    def cover(self, res, check, value):
        self.coverage.setdefault(res, {})[check] = value

    def worst(self):
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: SEVERITIES.index(f.severity)).severity

    def count_at_least(self, sev):
        i = SEVERITIES.index(sev)
        return sum(1 for f in self.findings if SEVERITIES.index(f.severity) >= i)

    def to_dict(self):
        return {"run_id": self.run_id, "findings": [f.to_dict() for f in self.findings],
                "coverage": self.coverage, "notes": self.notes,
                "identities": self.identities}


def _rows(n):
    return f"{n} row" + ("" if n == 1 else "s")


class Unseedable(Exception):
    pass


def _denied(r):
    return r.status in (401, 403) or (r.status >= 400 and "42501" in r.text)


class Scanner:
    def __init__(self, target, tables=(), public=(), owners=None, skip=(), seed=True,
                 user_tokens=(), log=None, storage=True):
        self.t = target
        self.extra_tables = list(tables)
        self.public = set(public)
        self.owners = dict(owners or {})
        self.skip = set(skip)
        self.seed = seed
        self.user_tokens = list(user_tokens)
        self.storage = storage
        self.log = log or (lambda *_: None)
        self.run_id = secrets.token_hex(3)
        self.res = ScanResult(self.run_id)
        self.users = []
        self.marker = f"authzprobe-{self.run_id}"
        self._fk_cache = {}
        self._generated = {}

    # ------------------------------------------------------------------
    def run(self):
        resources, rpcs = self._schema()
        try:
            self._make_users()
            for name in sorted(resources):
                self._check_resource(resources[name])
            if self.storage:
                self._check_storage()
            if rpcs:
                shown = ", ".join(rpcs[:12]) + (" ..." if len(rpcs) > 12 else "")
                self.res.add("AP070", "info", "rpc", "anon", f"{len(rpcs)} RPC function{'' if len(rpcs) == 1 else 's'} exposed to the Data API",
                             f"{shown}. SECURITY DEFINER functions skip RLS, so check each one does its own "
                             "auth.uid() check. authzprobe does not call RPCs (they may have side effects).",
                             "revoke execute on function public.<fn> from anon;  -- for functions anon shouldn't call")
        finally:
            for u in self.users:
                try:
                    self.t.delete_user(u)
                except Exception:
                    pass
        return self.res

    # ------------------------------------------------------------------
    def _schema(self):
        t = self.t
        spec = None
        r_anon = t.openapi(t.anon)
        data = r_anon.json() if r_anon.ok else None
        if isinstance(data, dict) and data.get("paths"):
            self.res.add("AP002", "low", "/rest/v1/", "anon", "The anon key can read the full API schema",
                         "Every table, column and RPC name is listed to anyone with the public key.",
                         fixes.fix_openapi())
            spec = data
        if t.service:
            r = t.openapi(t.service)
            d = r.json() if r.ok else None
            if isinstance(d, dict) and d.get("paths"):
                spec = d
            else:
                self.res.notes.append(f"could not read the OpenAPI schema with the service key (HTTP {r.status})")
        resources, rpcs = parse_openapi(spec) if spec else ({}, [])
        if not spec:
            self.res.notes.append("schema not readable with the keys given: testing only the tables you named "
                                  "(--tables / --from-site), without column info")
        for name in self.extra_tables:
            resources.setdefault(name, Resource(name, methods={"get", "post", "patch", "delete"}))
        for name in list(resources):
            if name in self.skip:
                del resources[name]
        if not resources:
            raise TargetError("no tables to test: pass --service-key / --jwt-secret so authzprobe can read the "
                              "schema, or name tables with --tables or --from-site")
        for r in resources.values():
            r.guess_owner(self.owners)
        self.log(f"schema: {len(resources)} tables/views, {len(rpcs)} RPCs")
        return resources, rpcs

    def _make_users(self):
        if self.user_tokens:
            for i, tok in enumerate(self.user_tokens[:2]):
                p = decode_unverified(tok) or {}
                self.users.append(Identity("user " + "AB"[i], token=tok, user_id=p.get("sub"), email=p.get("email")))
            self.users_fresh = False
        else:
            self.users_fresh = True
            try:
                for label in ("user A", "user B"):
                    self.users.append(self.t.make_user(label, self.run_id))
            except TargetError as e:
                self.res.notes.append(f"two-user tests skipped: {e}")
        self.res.identities = [{"name": u.name, "user_id": u.user_id, "email": u.email,
                                "created": u.admin_created} for u in self.users]
        if self.users:
            self.log("identities: anon, " + ", ".join(f"{u.name} ({(u.user_id or '?')[:8]})" for u in self.users))

    # ------------------------------------------------------------------
    def _sev_for(self, res, cols, base):
        sens = [c for c in cols if is_sensitive(c)]
        if sens:
            return "critical", sens
        return base, sens

    def _check_resource(self, res):
        t, name = self.t, res.name
        cols = list(res.columns)
        total = None
        if t.service:
            total, _ = t.count(name, t.service)
            self.res.cover(name, "rows", total)
        # --- anon read of existing rows
        n_anon, r = t.count(name, t.anon)
        self.res.cover(name, "anon read", n_anon if n_anon is not None else f"denied ({r.status})")
        if n_anon:
            if not cols:
                cols = self._learn_columns(res, t.anon)
            if name in self.public:
                self.res.cover(name, "public", True)
            else:
                sev, sens = self._sev_for(res, cols, "high")
                self.res.add("AP010", sev, name, "anon",
                             f"Anyone with the public key can read {_rows(n_anon)} of {name}",
                             " ".join(x for x in (
                                 f"Sensitive-looking columns: {', '.join(sens)}." if sens else "",
                                 "That is every row in the table." if total is not None and n_anon >= total else "")
                                 if x),
                             fixes.fix_for("anon-read", name, res.owner, "anon"))
        if not self.users:
            return
        a = self.users[0]
        filters = None
        if res.owner and a.user_id and not self.users_fresh:
            filters = {res.owner: f"neq.{a.user_id}"}
        n_a, r = t.count(name, a, filters)
        self.res.cover(name, "user A read", n_a if n_a is not None else f"denied ({r.status})")
        if n_a and name not in self.public:
            if not cols:
                cols = self._learn_columns(res, a)
            if res.owner:
                if not self._has(name, "AP010"):
                    sev, sens = self._sev_for(res, cols, "high")
                    self.res.add("AP011", sev, name, "user A",
                                 f"A signed-in user can read {_rows(n_a)} of {name} that belong to other users",
                                 f"{'A brand-new' if self.users_fresh else 'The test'} user "
                                 f"{'owns no rows yet' if self.users_fresh else 'is filtered out'}, so every row it "
                                 f"sees is someone else's (owner column: {res.owner})." +
                                 (f" Sensitive-looking columns: {', '.join(sens)}." if sens else ""),
                                 fixes.fix_for("read", name, res.owner, "user"))
            elif total is not None and n_a >= total and (n_anon or 0) < n_a:
                self.res.add("AP012", "medium", name, "user A",
                             f"Every signed-in user can read all {n_a} rows of {name}",
                             "No owner column was found, so authzprobe can't tell whose rows these are. Fine for "
                             "shared data; a leak if rows belong to users or teams. Use --owner TABLE=COLUMN or "
                             "--public TABLE to settle it.",
                             fixes.fix_for("all-users-read", name))
        # --- seeded two-user tests
        if not self.seed:
            return
        why = None
        if len(self.users) < 2:
            why = "needs two users"
        elif not t.service:
            why = "needs --service-key or --jwt-secret (to seed and clean up)"
        elif not res.owner:
            why = "no owner column (use --owner TABLE=COLUMN)"
        elif res.columns and not ({"post", "patch"} & res.methods):
            why = "read-only (view or no insert grant)"
        elif not self.users[1].user_id:
            why = "user B has no id"
        if why:
            self.res.cover(name, "two-user", f"skipped: {why}")
            return
        try:
            self._two_user(res, cols)
        except Unseedable as e:
            self.res.cover(name, "two-user", f"skipped: {e}")
        finally:
            self._cleanup(res)

    # ------------------------------------------------------------------
    def _learn_columns(self, res, ident):
        """No schema: learn column names from one visible row (values are never stored)."""
        from .schema import Column
        cols = self.t.sample_columns(res.name, ident)
        if cols and not res.columns:
            res.columns = {c: Column(c, {}, False) for c in cols}
            res.guess_owner(self.owners)
        return cols

    def _has(self, table, *ids):
        return any(f.resource == table and f.id in ids for f in self.res.findings)

    def _fk_value(self, table, column):
        key = (table, column)
        if key not in self._fk_cache:
            r = self.t.rest_call("GET", table, self.t.service, params={"select": column, "limit": "1"})
            rows = r.json() if r.ok else None
            self._fk_cache[key] = rows[0][column] if isinstance(rows, list) and rows else None
        return self._fk_cache[key]

    def _synth(self, res, owner_id, marker):
        row = {}
        now = datetime.datetime.now(datetime.timezone.utc)
        for c in res.columns.values():
            if c.name == res.owner:
                row[c.name] = owner_id
                continue
            if not c.required and not (c.is_text and c.name == res.text_column):
                continue
            if c.name in self._generated.get(res.name, ()):
                continue
            if c.pk and c.format in ("integer", "bigint", "smallint"):
                continue  # identity / serial
            if c.fk and c.fk[0] != res.name:
                v = self._fk_value(*c.fk)
                if v is None:
                    raise Unseedable(f"required column {c.name} references {c.fk[0]}.{c.fk[1]}, which has no rows")
                row[c.name] = v
            elif c.enum:
                row[c.name] = c.enum[0]
            elif c.is_uuid:
                row[c.name] = str(uuid.uuid4())
            elif c.is_text:
                row[c.name] = marker
            elif c.format in ("integer", "bigint", "smallint", "numeric", "real", "double precision"):
                row[c.name] = 1
            elif c.format == "boolean":
                row[c.name] = False
            elif c.format.startswith("timestamp"):
                row[c.name] = now.isoformat()
            elif c.format == "date":
                row[c.name] = now.date().isoformat()
            elif c.format.startswith("time"):
                row[c.name] = "12:00:00"
            elif c.format in ("json", "jsonb"):
                row[c.name] = {}
            elif c.type == "array":
                row[c.name] = []
            else:
                raise Unseedable(f"don't know how to fill required column {c.name} ({c.format or c.type})")
        if not row:
            row[res.owner] = owner_id
        return row

    def _insert(self, res, actor, row):
        """POST a row; if Postgres says a column is generated, drop it and retry."""
        for _ in range(4):
            r = self.t.rest_call("POST", res.name, actor, body=row, prefer="return=minimal")
            msg = r.text
            if r.status == 400 and ("428C9" in msg or "generated column" in msg):
                m = re.search(r'column \\?"([^"\\]+)\\?"', msg)
                if m and m.group(1) in row:
                    self._generated.setdefault(res.name, set()).add(m.group(1))
                    row = {k: v for k, v in row.items() if k != m.group(1)}
                    continue
            return r
        return r

    def _owned(self, res, uid):
        return {res.owner: f"eq.{uid}"}

    def _exists(self, res, filters):
        n, _ = self.t.count(res.name, self.t.service, filters)
        return n or 0

    def _seed(self, res, b):
        row = self._synth(res, b.user_id, self.marker)
        r = self._insert(res, b, row)
        if r.ok:
            return "user B"
        r2 = self._insert(res, self.t.service, row)
        if not r2.ok:
            raise Unseedable(f"could not insert a test row: HTTP {r2.status} {r2.error_message()}")
        return "service (user B's insert was refused: " + (r.error_message() or str(r.status)) + ")"

    def _two_user(self, res, cols):
        t, name = self.t, res.name
        a, b = self.users[0], self.users[1]
        mine = self._owned(res, b.user_id)
        sev_base, sens = self._sev_for(res, cols, "high")
        # 1) forged inserts: rows claiming to belong to user B, before B has any rows
        for actor, fid in ((t.anon, "AP050"), (a, "AP051")):
            row = self._synth(res, b.user_id, self.marker + "-forged")
            r = self._insert(res, actor, row)
            label = "anon" if actor is t.anon else "user A"
            if r.ok and self._exists(res, mine):
                self.res.cover(name, f"{label} insert as B", "ALLOWED")
                if not self._has(name, "AP050"):
                    self.res.add(fid, "high", name, label,
                             f"{'Anyone' if actor is t.anon else 'A signed-in user'} can create {name} rows "
                             "owned by another user",
                             f"Inserted a row with {res.owner} = user B's id as {label}.",
                             fixes.fix_for("insert", name, res.owner, "anon" if actor is t.anon else "user"))
                t.rest_call("DELETE", name, t.service, params=mine, prefer="return=minimal")
            else:
                self.res.cover(name, f"{label} insert as B",
                               "denied" if (_denied(r) or r.ok) else f"inconclusive ({r.status} {r.error_message()})")
        # 2) seed a row as user B
        how = self._seed(res, b)
        if not self._exists(res, mine):
            raise Unseedable("test row was inserted but the service key can't see it")
        self.res.cover(name, "seeded by", how)
        # 3) reads
        for actor, fid in ((t.anon, "AP020"), (a, "AP021")):
            label = "anon" if actor is t.anon else "user A"
            n, r = t.count(name, actor, mine)
            self.res.cover(name, f"{label} read B's row", "ALLOWED" if n else "denied")
            if n and name not in self.public and not self._has(name, "AP010", "AP011", "AP020"):
                self.res.add(fid, "critical" if (sens or actor is t.anon) else sev_base, name, label,
                             f"{'Anyone' if actor is t.anon else 'User A'} can read user B's {name} rows",
                             "Seeded a row as user B and read it back as " + label + "." +
                             (f" Sensitive-looking columns: {', '.join(sens)}." if sens else ""),
                             fixes.fix_for("anon-read" if actor is t.anon else "read", name, res.owner,
                                           "anon" if actor is t.anon else "user"))
        # 4) updates
        tc = res.text_column
        for actor, fid in ((t.anon, "AP030"), (a, "AP031")):
            label = "anon" if actor is t.anon else "user A"
            if tc:
                tampered = self.marker + "-tampered"
                r = t.rest_call("PATCH", name, actor, params=mine, body={tc: tampered}, prefer="return=minimal")
                changed = self._exists(res, dict(mine, **{tc: f"eq.{tampered}"})) > 0
                if changed:
                    t.rest_call("PATCH", name, t.service, params=mine, body={tc: self.marker}, prefer="return=minimal")
            else:
                r = t.rest_call("PATCH", name, actor, params=mine, body={res.owner: b.user_id},
                                prefer="return=minimal,count=exact")
                cr = r.headers.get("content-range", "")
                changed = r.ok and cr.rsplit("/", 1)[-1] not in ("0", "*", "")
            self.res.cover(name, f"{label} update B's row", "ALLOWED" if changed else "denied")
            if changed and not self._has(name, "AP030"):
                self.res.add(fid, "critical" if actor is t.anon else "high", name, label,
                             f"{'Anyone' if actor is t.anon else 'User A'} can change user B's {name} rows",
                             f"PATCH as {label} modified the row seeded for user B" + (f" (column {tc})." if tc else "."),
                             fixes.fix_for("update", name, res.owner, "anon" if actor is t.anon else "user"))
        # 5) deletes
        for actor, fid in ((t.anon, "AP040"), (a, "AP041")):
            label = "anon" if actor is t.anon else "user A"
            if not self._exists(res, mine):
                self._seed(res, b)
            t.rest_call("DELETE", name, actor, params=mine, prefer="return=minimal")
            gone = self._exists(res, mine) == 0
            self.res.cover(name, f"{label} delete B's row", "ALLOWED" if gone else "denied")
            if gone and not self._has(name, "AP040"):
                self.res.add(fid, "critical" if actor is t.anon else "high", name, label,
                             f"{'Anyone' if actor is t.anon else 'User A'} can delete user B's {name} rows",
                             f"DELETE as {label} removed the row seeded for user B.",
                             fixes.fix_for("delete", name, res.owner, "anon" if actor is t.anon else "user"))
        self.res.cover(name, "two-user", "tested")

    def _cleanup(self, res):
        if len(self.users) >= 2 and res.owner and self.t.service and self.users[1].user_id:
            self.t.rest_call("DELETE", res.name, self.t.service, params=self._owned(res, self.users[1].user_id),
                             prefer="return=minimal")

    # ------------------------------------------------------------------
    def _check_storage(self):
        t = self.t
        if not t.url or t.rest != t.url + "/rest/v1":
            return
        who = t.service or t.anon
        r = t.buckets(who)
        data = r.json() if r.ok else None
        if not isinstance(data, list):
            self.res.cover("storage", "buckets", f"not checked (HTTP {r.status})")
            return
        self.res.cover("storage", "buckets", len(data))
        for bk in data:
            bid = bk.get("id") or bk.get("name")
            if not bid:
                continue
            if bk.get("public"):
                sensitive = is_sensitive(bid) or any(w in bid.lower() for w in
                                                    ("id", "doc", "kyc", "private", "verif", "upload", "selfie"))
                self.res.add("AP061", "medium" if sensitive else "info", f"storage:{bid}", "anon",
                             f"Bucket {bid} is public: anyone with a file URL can download its files",
                             "Fine for avatars and site images; not for IDs, documents or user uploads. "
                             "(The Tea app leak was a public bucket.)", fixes.fix_bucket_public(bid))
                continue
            actors = [(t.anon, "anon", "high")] + ([(self.users[0], "user A", "high")] if self.users else [])
            for actor, label, sev in actors:
                rr = t.list_objects(bid, actor)
                items = rr.json() if rr.ok else None
                n = len(items) if isinstance(items, list) else 0
                self.res.cover(f"storage:{bid}", f"{label} list", n if rr.ok else f"denied ({rr.status})")
                if n and (label == "anon" or self.users_fresh):
                    self.res.add("AP060", sev, f"storage:{bid}", label,
                                 f"{'Anyone' if label == 'anon' else 'Any signed-in user'} can list files in the "
                                 f"private bucket {bid}",
                                 f"Listing the bucket root as {label} returned {n} entries"
                                 + (" (a brand-new user owns no files, so these are other users')." if label != "anon" else "."),
                                 fixes.fix_bucket_list(bid))
                    break
