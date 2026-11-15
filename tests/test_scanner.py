import pytest

from authzprobe.probe import Scanner
from authzprobe.target import Target, TargetError
from fakebackend import ANON, SECRET, SERVICE, FakeBackend, Table, anyone, authed, nobody, owner

ALICE = "11111111-1111-4111-8111-111111111111"
URL = "https://proj.supabase.test"


def tables():
    return [
        Table("profiles", {"id": "uuid", "email": "text"}, [{"id": ALICE, "email": "a@x"}],
              select=authed, insert=owner("id"), update=owner("id"), pk="id", pk_identity=False),
        Table("notes", {"id": "bigint", "user_id": "uuid", "title": "text"},
              [{"id": 1, "user_id": ALICE, "title": "t"}],
              select=owner("user_id"), insert=owner("user_id"), update=owner("user_id"), delete=owner("user_id")),
        Table("orders", {"id": "bigint", "user_id": "uuid", "status": "text"},
              [{"id": 1, "user_id": ALICE, "status": "paid"}],
              select=anyone, insert=anyone, update=anyone, delete=anyone),
        Table("posts", {"id": "bigint", "author_id": "uuid", "title": "text"},
              [{"id": 1, "author_id": ALICE, "title": "hi"}],
              select=anyone, insert=owner("author_id"), update=authed, delete=owner("author_id")),
        Table("settings", {"id": "bigint", "theme": "text"}, [{"id": 1, "theme": "dark"}], select=authed),
    ]


def run(backend=None, **kw):
    be = backend or FakeBackend(tables(), buckets={
        "avatars": {"public": True, "objects": ["a.png"]},
        "ids": {"public": False, "list": "authenticated", "objects": [ALICE]},
        "receipts": {"public": False, "list": "owner", "objects": [ALICE]},
    })
    t = Target(URL, anon_key=ANON, service_key=SERVICE, request=be)
    res = Scanner(t, **kw).run()
    return res, be


def ids(res, table=None):
    return sorted((f.id, f.resource) for f in res.findings if table is None or f.resource == table)


def test_correct_table_has_no_findings_and_full_coverage():
    res, _ = run()
    assert ids(res, "notes") == []
    cov = res.coverage["notes"]
    assert cov["two-user"] == "tested"
    assert cov["user A read B's row"] == "denied"
    assert cov["anon delete B's row"] == "denied"


def test_profiles_readable_by_any_user_is_critical():
    res, _ = run()
    f = [x for x in res.findings if x.resource == "profiles"]
    assert [x.id for x in f] == ["AP011"]
    assert f[0].severity == "critical" and "email" in f[0].detail


def test_open_table_anon_read_update_delete_insert():
    res, _ = run()
    assert {i for i, _ in ids(res, "orders")} == {"AP010", "AP030", "AP040", "AP050"}


def test_public_table_skips_read_but_catches_update():
    res, _ = run(public=["posts"])
    assert ids(res, "posts") == [("AP031", "posts")]
    assert res.coverage["posts"]["public"] is True


def test_no_owner_table_readable_by_all_users_is_medium():
    res, _ = run()
    f = [x for x in res.findings if x.resource == "settings"]
    assert [(x.id, x.severity) for x in f] == [("AP012", "medium")]
    assert res.coverage["settings"]["two-user"].startswith("skipped: no owner column")


def test_owner_override_enables_two_user():
    res, _ = run(owners={"settings": "id"}, skip=["orders"])
    assert "orders" not in res.coverage
    assert not res.coverage["settings"]["two-user"].startswith("skipped: no owner")


def test_storage_findings():
    res, _ = run()
    st = {(f.id, f.resource, f.severity) for f in res.findings if f.resource.startswith("storage")}
    assert ("AP060", "storage:ids", "high") in st
    assert ("AP061", "storage:avatars", "info") in st
    assert not any(r == "storage:receipts" for _, r, _ in st)


def test_rpc_info_and_schema_privacy():
    res, _ = run()
    assert ("AP070", "rpc") in ids(res)
    assert ("AP002", "/rest/v1/") not in ids(res)
    be = FakeBackend(tables(), openapi_for_anon=True)
    res2, _ = run(be)
    assert ("AP002", "/rest/v1/") in ids(res2)


def test_cleanup_removes_test_users_and_rows():
    res, be = run()
    assert be.users == {}
    for t in be.tables.values():
        for r in t.rows:
            assert "authzprobe" not in str(r.get("title", "")) + str(r.get("status", "")) + str(r.get("email", ""))
    assert sum(len(t.rows) for t in be.tables.values()) == 5


def test_no_seed_is_read_only():
    res, be = run(seed=False)
    writes = [c for c in be.calls if c[0] in ("POST", "PATCH", "DELETE") and "/rest/v1/" in c[1]]
    assert writes == []
    assert ("AP010", "orders") in ids(res)
    assert ("AP030", "orders") not in ids(res)


def test_anon_only_mode_without_service_key():
    be = FakeBackend(tables())
    t = Target(URL, anon_key=ANON, request=be)
    res = Scanner(t, tables=["orders", "notes"]).run()
    assert ids(res) == [("AP010", "orders")]
    assert any("two-user tests skipped" in n for n in res.notes)
    assert any("schema not readable" in n for n in res.notes)


def test_user_tokens_mode_filters_own_rows():
    from authzprobe.jwtutil import mint
    be = FakeBackend(tables())
    t = Target(URL, anon_key=ANON, request=be)
    a = mint(SECRET, {"sub": ALICE, "role": "authenticated"})
    b = mint(SECRET, {"sub": "33333333-3333-4333-8333-333333333333", "role": "authenticated"})
    res = Scanner(t, tables=["notes", "profiles"], user_tokens=[a, b], owners={"notes": "user_id"}).run()
    # Alice sees her own note, which must not count as a leak.
    assert ("AP011", "notes") not in ids(res)


def test_jwt_secret_mints_users_when_no_auth_server():
    be = FakeBackend(tables(), admin=False)
    t = Target(URL, jwt_secret=SECRET, request=be)
    res = Scanner(t).run()
    assert res.coverage["notes"]["two-user"] == "tested"
    assert len(res.identities) == 2


def test_no_tables_is_an_error():
    be = FakeBackend([])
    t = Target(URL, anon_key=ANON, request=be)
    with pytest.raises(TargetError):
        Scanner(t).run()


def test_rejects_swapped_keys():
    with pytest.raises(TargetError):
        Target(URL, anon_key=SERVICE)
    with pytest.raises(TargetError):
        Target(URL, anon_key=ANON, service_key=ANON)


def test_new_style_keys_send_apikey_only():
    t = Target(URL, anon_key="sb_publishable_abcdefghijklmn", service_key="sb_secret_abcdefghijklmn")
    h = t.headers(t.service)
    assert h == {"apikey": "sb_secret_abcdefghijklmn"}
    assert "Authorization" not in t.headers(t.anon)


def test_unseedable_fk_reported_as_skipped():
    tb = Table("items", {"id": "bigint", "user_id": "uuid", "shop_id": "bigint"}, [], select=nobody)
    be = FakeBackend([tb])
    spec = be.spec()
    spec["definitions"]["items"]["properties"]["shop_id"]["description"] = "<fk table='shops' column='id'/>"
    be.spec = lambda: spec
    be.tables["shops"] = Table("shops", {"id": "bigint"}, [])
    res, _ = run(be)
    assert "references shops.id" in res.coverage["items"]["two-user"]


def test_severity_counts():
    res, _ = run()
    assert res.worst() == "critical"
    assert res.count_at_least("high") >= 5
    assert res.count_at_least("info") == len(res.findings)
