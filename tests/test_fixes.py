from authzprobe import fixes


def test_owner_policy_shapes():
    s = fixes.owner_policy("orders", "user_id", "read")
    assert 'for select to authenticated using ((select auth.uid()) = "user_id")' in s
    u = fixes.owner_policy("orders", "user_id", "update")
    assert "using (" in u and "with check (" in u
    i = fixes.owner_policy("orders", "user_id", "insert")
    assert "for insert to authenticated with check" in i and "using" not in i


def test_fix_for_anon_with_owner_revokes():
    s = fixes.fix_for("anon-read", "messages", "user_id", "anon")
    assert "enable row level security" in s
    assert 'revoke select on public."messages" from anon;' in s


def test_fix_for_no_owner_mentions_public_flag():
    s = fixes.fix_for("anon-read", "posts", None, "anon")
    assert "--public posts" in s
    assert "revoke select, insert, update, delete" in s


def test_quote_identifiers():
    assert fixes.t('we"ird') == 'public."we""ird"'


def test_bucket_fixes():
    assert "public = false" in fixes.fix_bucket_public("ids")
    assert "storage.foldername(name)" in fixes.fix_bucket_list("docs")
