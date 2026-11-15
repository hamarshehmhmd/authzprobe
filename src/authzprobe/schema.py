"""Resources (tables/views, RPCs) and their columns, from PostgREST's OpenAPI spec."""
import re

OWNER_NAMES = ("user_id", "owner_id", "owner", "created_by", "author_id", "profile_id",
               "account_id", "uid", "member_id", "creator_id", "customer_id", "auth_id")
SELF_TABLES = ("profiles", "profile", "users", "user_profiles", "accounts", "members", "user_settings")
SENSITIVE_SUBSTR = ("email", "e_mail", "phone", "mobile", "passport", "password", "passwd", "secret",
                    "token", "apikey", "api_key", "private_key", "iban", "salary", "income", "address",
                    "birth", "diagnos", "medical", "health", "message", "license_number", "social_security",
                    "national_id", "tax_id", "card_number", "credit_card")
SENSITIVE_TOKENS = {"ssn", "dob", "cvv", "card", "bank", "street", "postcode", "zip", "ip", "lat", "lng",
                    "geo", "location", "body", "content", "note", "notes", "chat", "dm", "id_number"}


def is_sensitive(name):
    n = name.lower()
    if any(s in n for s in SENSITIVE_SUBSTR):
        return True
    return any(t in SENSITIVE_TOKENS for t in n.split("_"))


FK_RE = re.compile(r"<fk table='([^']+)' column='([^']+)'/>")


class Column:
    def __init__(self, name, prop, required):
        self.name = name
        self.type = prop.get("type")
        self.format = prop.get("format") or ""
        self.enum = prop.get("enum")
        self.has_default = "default" in prop
        desc = prop.get("description") or ""
        self.pk = "<pk/>" in desc
        m = FK_RE.search(desc)
        self.fk = (m.group(1), m.group(2)) if m else None
        self.required = required
        self.items = prop.get("items")

    @property
    def is_uuid(self):
        return self.format == "uuid"

    @property
    def is_text(self):
        return self.format in ("text", "character varying", "character", "citext") and not self.enum

    @property
    def sensitive(self):
        return is_sensitive(self.name)


class Resource:
    def __init__(self, name, columns=None, methods=None):
        self.name = name
        self.columns = columns or {}
        self.methods = methods or {"get"}
        self.owner = None

    @property
    def pk(self):
        pks = [c.name for c in self.columns.values() if c.pk]
        return pks[0] if len(pks) == 1 else None

    @property
    def sensitive_columns(self):
        return [c.name for c in self.columns.values() if c.sensitive]

    @property
    def text_column(self):
        for c in self.columns.values():
            if c.is_text and not c.pk and c.name != self.owner and not c.fk:
                return c.name
        return None

    def guess_owner(self, overrides=None):
        overrides = overrides or {}
        if self.name in overrides:
            self.owner = overrides[self.name]
            return self.owner
        cols = self.columns
        for n in OWNER_NAMES:
            c = cols.get(n)
            if c is not None and (c.is_uuid or not c.format):
                self.owner = n
                return n
        pk = self.pk
        if pk and cols[pk].is_uuid and self.name.lower() in SELF_TABLES:
            self.owner = pk
            return pk
        return None


def parse_openapi(spec):
    """Return (resources: dict name->Resource, rpcs: list of names)."""
    definitions = spec.get("definitions") or {}
    paths = spec.get("paths") or {}
    resources = {}
    rpcs = []
    for path, ops in paths.items():
        if path == "/":
            continue
        if path.startswith("/rpc/"):
            rpcs.append(path[5:])
            continue
        name = path.lstrip("/")
        d = definitions.get(name) or {}
        required = set(d.get("required") or [])
        cols = {cn: Column(cn, p, cn in required) for cn, p in (d.get("properties") or {}).items()}
        resources[name] = Resource(name, cols, {m.lower() for m in ops})
    return resources, sorted(rpcs)
