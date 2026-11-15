"""Suggested SQL for each kind of finding (Supabase / Postgres RLS)."""


def q(name):
    return '"' + name.replace('"', '""') + '"'


def t(table, schema="public"):
    return f"{schema}.{q(table)}"


def rls_on(table):
    return f"alter table {t(table)} enable row level security;"


def owner_policy(table, owner, action):
    cmd = {"read": "select", "update": "update", "delete": "delete", "insert": "insert"}[action]
    check = f"(select auth.uid()) = {q(owner)}"
    name = q(f"{table}: owner can {cmd}")
    if cmd == "insert":
        return f"create policy {name} on {t(table)} for insert to authenticated with check ({check});"
    if cmd == "update":
        return (f"create policy {name} on {t(table)} for update to authenticated\n"
                f"  using ({check}) with check ({check});")
    return f"create policy {name} on {t(table)} for {cmd} to authenticated using ({check});"


def fix_for(kind, table, owner=None, actor="anon", is_view=False):
    lines = []
    if kind in ("anon-read", "anon-write") and not owner:
        lines += [
            "-- If this table is not meant to be public:",
            rls_on(table),
            f"revoke select, insert, update, delete on {t(table)} from anon;",
            "-- then add policies for the authenticated role that match how rows are owned.",
            "-- If it IS public on purpose, run authzprobe with --public " + table + ".",
        ]
    elif kind == "all-users-read":
        lines += [
            f"-- Every signed-in user can read every row of {table}, and authzprobe found no owner column.",
            "-- If rows belong to users or teams, add an owner column and scope the select policy:",
            f"--   alter table {t(table)} add column user_id uuid references auth.users default auth.uid();",
            "--   " + owner_policy(table, "user_id", "read").replace("\n", "\n--   "),
            "-- If it is shared reference data, mark it with --public " + table + ".",
        ]
    elif owner:
        action = {"read": "read", "anon-read": "read", "update": "update", "delete": "delete",
                  "insert": "insert", "anon-write": "update"}.get(kind, "read")
        lines += [
            rls_on(table),
            "-- Find and drop the policy that is too broad (often `using (true)`, `to public`,",
            "-- `auth.role() = 'authenticated'` or an inverted check):",
            f"--   select policyname, roles, cmd, qual, with_check from pg_policies where tablename = '{table}';",
            owner_policy(table, owner, action),
        ]
        if actor == "anon":
            lines.append(f"revoke {'select' if action == 'read' else action} on {t(table)} from anon;")
    lines.append(f"-- If {table} is a view: views ignore RLS unless created with "
                 f"`alter view {t(table)} set (security_invoker = on);`")
    return "\n".join(lines)


def fix_bucket_public(bucket):
    return (f"update storage.buckets set public = false where id = '{bucket}';\n"
            "-- then serve files with signed URLs (createSignedUrl) instead of public URLs.")


def fix_bucket_list(bucket):
    return ("-- Scope storage.objects policies to the user's own folder, e.g.:\n"
            f"create policy \"{bucket}: own folder\" on storage.objects for select to authenticated\n"
            f"  using (bucket_id = '{bucket}' and (storage.foldername(name))[1] = (select auth.uid())::text);")


def fix_service_key():
    return ("Rotate the service_role / sb_secret_ key now (Project Settings > API keys), remove it from the\n"
            "frontend code and env vars prefixed VITE_ / NEXT_PUBLIC_, and only use it server-side.")


def fix_openapi():
    return ("Self-hosted gateway: restrict GET /rest/v1/ to service_role (Supabase did this on its platform\n"
            "on 2026-04-08), or set `db-root-spec` / `openapi-mode = disabled` in PostgREST.")
