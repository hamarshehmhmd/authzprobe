"""End-to-end against real Postgres + real PostgREST (scripts/localstack.py).

Skipped when Postgres server binaries or postgrest aren't installed. CI runs them.
"""
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import localstack  # noqa: E402

from authzprobe.discover import discover  # noqa: E402
from authzprobe.probe import Scanner  # noqa: E402
from authzprobe.target import Target  # noqa: E402

pytestmark = pytest.mark.skipif(
    not (localstack.find_pg_bin() and localstack.find_postgrest()) and not os.environ.get("AUTHZPROBE_REQUIRE_E2E"),
    reason="needs Postgres server binaries and postgrest")
SCHEMA = os.path.join(ROOT, "examples", "vibeapp", "schema.sql")
FIXED = os.path.join(ROOT, "examples", "vibeapp", "fixed.sql")


@pytest.fixture(scope="module")
def stack():
    st = localstack.Stack([SCHEMA]).start()
    yield st
    st.stop()


def ids(res):
    return {(f.id, f.resource) for f in res.findings}


def scan(st, **kw):
    t = Target(st.url, anon_key=st.anon_key, service_key=st.service_key)
    return Scanner(t, public=["posts"], **kw).run()


def test_finds_every_planted_bug(stack):
    res = scan(stack)
    got = ids(res)
    assert ("AP011", "profiles") in got       # any logged-in user reads all profiles
    assert ("AP010", "messages") in got       # inverted guard: anon reads everything
    assert {("AP010", "orders"), ("AP030", "orders"), ("AP040", "orders"), ("AP050", "orders")} <= got
    assert ("AP031", "posts") in got          # using (true) on update
    assert ("AP060", "storage:documents") in got
    assert not any(r == "notes" for _, r in got)  # the correct table stays clean
    assert res.coverage["notes"]["two-user"] == "tested"
    assert res.coverage["profiles"]["user A update B's row"] == "denied"


def test_leaves_no_test_rows_behind(stack):
    scan(stack)
    out = subprocess.run([os.path.join(stack.pg_bin, "psql") if os.path.exists(os.path.join(stack.pg_bin, "psql"))
                          else "psql", "-h", "127.0.0.1", "-p", str(stack.pg_port), "-U", "postgres", "-tAc",
                          "select (select count(*) from profiles) + (select count(*) from messages) + "
                          "(select count(*) from orders) + (select count(*) from notes) + "
                          "(select count(*) from posts)"], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "8"
    assert stack.users == {}


def test_bare_postgrest_with_jwt_secret(stack):
    t = Target(None, jwt_secret=localstack.JWT_SECRET, rest_url=stack.rest_url)
    res = Scanner(t, public=["posts"], storage=False).run()
    assert ("AP011", "profiles") in ids(res) and ("AP050", "orders") in ids(res)


def test_discover_from_site(stack):
    d = discover(stack.url + "/")
    assert d.supabase_url == stack.url
    assert d.anon_key == stack.anon_key
    assert d.tables == {"profiles", "messages", "orders", "notes"}
    assert d.buckets == {"documents", "avatars"} and d.rpcs == {"get_user_stats"}


def test_cli_exit_codes_before_and_after_fix(stack):
    env = dict(os.environ, SUPABASE_URL=stack.url, SUPABASE_ANON_KEY=stack.anon_key,
               SUPABASE_SERVICE_ROLE_KEY=stack.service_key, NO_COLOR="1")
    cmd = [sys.executable, "-m", "authzprobe", "scan", "--public", "posts", "--no-storage", "-q"]
    env["PYTHONPATH"] = os.path.join(ROOT, "src")
    before = subprocess.run(cmd, env=env, capture_output=True, text=True)
    assert before.returncode == 1 and "CRITICAL" in before.stdout
    stack.psql(file=FIXED)
    stack.reload_schema()
    after = subprocess.run(cmd, env=env, capture_output=True, text=True)
    assert after.returncode == 0, after.stdout
    assert "CRITICAL" not in after.stdout and "HIGH" not in after.stdout
