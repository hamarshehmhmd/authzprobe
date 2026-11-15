"""authzprobe command line."""
import argparse
import json
import os
import sys

from . import __version__, report
from .discover import discover
from .probe import SEVERITIES, Scanner
from .target import Target, TargetError

EPILOG = """examples:
  authzprobe discover https://my-app.lovable.app
  authzprobe scan --url https://abcd.supabase.co --anon-key $ANON --service-key $SERVICE_ROLE
  authzprobe scan --from-site https://my-app.lovable.app --i-own-this     # anon-only, read-only
  authzprobe scan --url http://127.0.0.1:54321 --jwt-secret $JWT_SECRET  # local `supabase start`

Only test projects you own or are allowed to test.
"""


def _csv(values):
    out = []
    for v in values or []:
        out += [x.strip() for x in v.split(",") if x.strip()]
    return out


def build_parser():
    p = argparse.ArgumentParser(prog="authzprobe", description="Prove user A can't read user B's data in a "
                                "Supabase app: behavioral row-level security tests.",
                                epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"authzprobe {__version__}")
    sub = p.add_subparsers(dest="cmd")

    d = sub.add_parser("discover", help="find the Supabase project, key, tables, RPCs and buckets a site uses "
                       "(reads only the site's HTML/JS)")
    d.add_argument("site")
    d.add_argument("--json", action="store_true")
    d.add_argument("--max-files", type=int, default=40)

    s = sub.add_parser("scan", help="run anon and two-user authorization tests against a project",
                       epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    s.add_argument("--url", default=os.environ.get("SUPABASE_URL"), help="project URL (env SUPABASE_URL)")
    s.add_argument("--anon-key", default=os.environ.get("SUPABASE_ANON_KEY"),
                   help="anon / sb_publishable_ key (env SUPABASE_ANON_KEY)")
    s.add_argument("--service-key", default=os.environ.get("SUPABASE_SERVICE_ROLE_KEY"),
                   help="service_role / sb_secret_ key: reads the schema, creates 2 throwaway users, seeds and "
                   "cleans up test rows (env SUPABASE_SERVICE_ROLE_KEY)")
    s.add_argument("--jwt-secret", default=os.environ.get("SUPABASE_JWT_SECRET"),
                   help="legacy JWT secret: mint test-user tokens instead of creating users (env SUPABASE_JWT_SECRET)")
    s.add_argument("--rest-url", help="talk to a bare PostgREST at this URL instead of URL/rest/v1")
    s.add_argument("--from-site", metavar="URL", help="take URL, anon key and table names from a deployed site")
    s.add_argument("--user-token", action="append", default=[], metavar="JWT",
                   help="use existing users' access tokens (give twice: user A then user B)")
    s.add_argument("--tables", action="append", help="extra table names to test (comma separated)")
    s.add_argument("--public", action="append", help="tables that are meant to be world-readable")
    s.add_argument("--owner", action="append", metavar="TABLE=COLUMN", help="owner column for a table")
    s.add_argument("--skip", action="append", help="tables to leave alone")
    s.add_argument("--no-seed", action="store_true", help="read-only: don't insert/modify/delete test rows")
    s.add_argument("--no-storage", action="store_true", help="skip Storage bucket checks")
    s.add_argument("--i-own-this", action="store_true",
                   help="confirm you're allowed to test this project (required without a service key/JWT secret)")
    s.add_argument("--format", choices=["text", "json", "markdown", "github"], default="text")
    s.add_argument("--fix-sql", metavar="FILE", help="write the suggested fix SQL to FILE")
    s.add_argument("--fail-on", choices=SEVERITIES + ["never"], default="high",
                   help="exit 1 if a finding is at least this severe (default: high)")
    s.add_argument("--brief", action="store_true", help="text output without the fix SQL")
    s.add_argument("-q", "--quiet", action="store_true")
    return p


def cmd_discover(a):
    d = discover(a.site, max_files=a.max_files)
    if a.json:
        print(json.dumps(d.to_dict(), indent=2))
        return 0
    print(f"site:         {a.site}  ({len(d.files)} scripts read)")
    print(f"supabase url: {d.supabase_url or 'not found'}")
    print(f"public key:   {'found (' + d.anon_key[:16] + '...)' if d.anon_key else 'not found'}")
    if d.service_keys:
        print("\033[1;31mCRITICAL: a service_role / sb_secret_ key is in the site's JavaScript. Anyone can "
              "bypass all RLS. Rotate it now.\033[0m")
    print(f"tables:       {', '.join(sorted(d.tables)) or '-'}")
    print(f"rpcs:         {', '.join(sorted(d.rpcs)) or '-'}")
    print(f"buckets:      {', '.join(sorted(d.buckets)) or '-'}")
    if d.supabase_url and d.anon_key:
        print(f"\nnext: authzprobe scan --from-site {a.site} --i-own-this")
    return 2 if d.service_keys else 0


def cmd_scan(a):
    tables = _csv(a.tables)
    log = (lambda *_: None) if (a.quiet or a.format != "text") else (lambda m: print(m, file=sys.stderr))
    site_info = None
    if a.from_site:
        d = discover(a.from_site)
        site_info = d.to_dict()
        a.url = a.url or d.supabase_url
        a.anon_key = a.anon_key or d.anon_key
        tables += sorted(d.tables)
        log(f"from site: {d.supabase_url}, {len(d.tables)} tables named in the JS")
        if d.service_keys:
            print("CRITICAL AP001: a service_role / sb_secret_ key is in the site's JavaScript. Rotate it now.",
                  file=sys.stderr)
    if not (a.url or a.rest_url):
        print("authzprobe: need --url (or SUPABASE_URL), --rest-url or --from-site", file=sys.stderr)
        return 2
    if not (a.service_key or a.jwt_secret or a.i_own_this):
        print("authzprobe: without a service key or JWT secret, confirm you're allowed to test this project "
              "with --i-own-this (anon and --user-token checks only)", file=sys.stderr)
        return 2
    owners = {}
    for o in a.owner or []:
        if "=" not in o:
            print(f"authzprobe: --owner wants TABLE=COLUMN, got {o!r}", file=sys.stderr)
            return 2
        k, v = o.split("=", 1)
        owners[k.strip()] = v.strip()
    try:
        target = Target(a.url, anon_key=a.anon_key, service_key=a.service_key, jwt_secret=a.jwt_secret,
                        rest_url=a.rest_url)
        if not target.anon_key:
            print("authzprobe: need --anon-key (or --jwt-secret / --from-site)", file=sys.stderr)
            return 2
        scanner = Scanner(target, tables=tables, public=_csv(a.public), owners=owners, skip=_csv(a.skip),
                          seed=not a.no_seed, user_tokens=a.user_token, log=log, storage=not a.no_storage)
        result = scanner.run()
    except TargetError as e:
        print(f"authzprobe: {e}", file=sys.stderr)
        return 2
    except OSError as e:  # URLError, timeouts, refused connections
        print(f"authzprobe: can't reach {a.url or a.rest_url}: {getattr(e, 'reason', e)}", file=sys.stderr)
        return 2
    if site_info and site_info.get("service_key_in_bundle"):
        from . import fixes
        result.add("AP001", "critical", a.from_site, "anon", "A service_role / sb_secret_ key is in the site's "
                   "JavaScript", "Anyone can bypass every RLS policy with it.", fixes.fix_service_key())
    if a.format == "json":
        print(report.as_json(result, {"site": site_info} if site_info else None))
    elif a.format == "markdown":
        print(report.markdown(result), end="")
    elif a.format == "github":
        report.github(result)
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a", encoding="utf-8") as fh:
                fh.write(report.markdown(result))
    else:
        report.text(result, show_fix=not a.brief)
    if a.fix_sql:
        with open(a.fix_sql, "w", encoding="utf-8") as fh:
            fh.write(report.sql_file(result))
        log(f"wrote fix suggestions to {a.fix_sql}")
    if a.fail_on != "never" and result.count_at_least(a.fail_on):
        return 1
    return 0


def main(argv=None):
    p = build_parser()
    a = p.parse_args(argv)
    if a.cmd == "discover":
        try:
            return cmd_discover(a)
        except (RuntimeError, OSError) as e:
            print(f"authzprobe: {e}", file=sys.stderr)
            return 2
    if a.cmd == "scan":
        return cmd_scan(a)
    p.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
