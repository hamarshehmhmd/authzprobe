import io
import json

from authzprobe import cli, report
from authzprobe.probe import Scanner
from authzprobe.target import Target
from fakebackend import ANON, SERVICE
from test_scanner import URL, run


def test_text_report_matrix_and_fix(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    res, _ = run()
    buf = io.StringIO()
    report.text(res, buf)
    out = buf.getvalue()
    assert "anon: sees" in out
    assert "RIUD" in out           # orders: anon can do everything to B's row
    assert "····" in out           # notes: denied everywhere
    assert "create policy" in out
    assert "findings:" in out


def test_markdown_and_github_and_sql():
    res, _ = run()
    md = report.markdown(res)
    assert md.startswith("## authzprobe") and "| critical |" in md and "```sql" in md
    buf = io.StringIO()
    report.github(res, buf)
    assert "::error title=AP010 orders" in buf.getvalue()
    sql = report.sql_file(res)
    assert "Review before applying" in sql and 'on public."orders"' in sql


def test_json_report_roundtrip():
    res, _ = run()
    d = json.loads(report.as_json(res, {"site": None}))
    assert d["run_id"] == res.run_id and d["findings"] and "coverage" in d


def test_cli_requires_ownership_confirmation(capsys):
    rc = cli.main(["scan", "--url", URL, "--anon-key", ANON])
    assert rc == 2
    assert "--i-own-this" in capsys.readouterr().err


def test_cli_requires_url(capsys, monkeypatch):
    for v in ("SUPABASE_URL", "SUPABASE_ANON_KEY", "SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_JWT_SECRET"):
        monkeypatch.delenv(v, raising=False)
    assert cli.main(["scan", "--i-own-this"]) == 2


def test_cli_bad_owner_flag(capsys):
    rc = cli.main(["scan", "--url", URL, "--anon-key", ANON, "--service-key", SERVICE, "--owner", "nope"])
    assert rc == 2 and "TABLE=COLUMN" in capsys.readouterr().err


def test_cli_unreachable_host(capsys):
    rc = cli.main(["scan", "--url", "http://127.0.0.1:9", "--anon-key", ANON, "--i-own-this", "--tables", "x"])
    assert rc == 2 and "can't reach" in capsys.readouterr().err


def test_cli_scan_end_to_end_with_fake(monkeypatch, tmp_path, capsys):
    from fakebackend import FakeBackend
    from test_scanner import tables
    be = FakeBackend(tables())
    real_target = Target

    def fake_target(*a, **k):
        k["request"] = be
        return real_target(*a, **k)

    monkeypatch.setattr(cli, "Target", fake_target)
    fix = tmp_path / "fix.sql"
    rc = cli.main(["scan", "--url", URL, "--anon-key", ANON, "--service-key", SERVICE, "--format", "json",
                   "--fix-sql", str(fix), "--public", "posts"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert {f["resource"] for f in out["findings"]} >= {"orders", "profiles"}
    assert fix.read_text().count("create policy") >= 3
    rc = cli.main(["scan", "--url", URL, "--anon-key", ANON, "--service-key", SERVICE, "--format", "json",
                   "--fail-on", "never"])
    assert rc == 0


def test_cli_version_and_help(capsys):
    import pytest
    with pytest.raises(SystemExit):
        cli.main(["--version"])
    assert "authzprobe 0.1.0" in capsys.readouterr().out
    assert cli.main([]) == 0
