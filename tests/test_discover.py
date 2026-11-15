from authzprobe.discover import discover, scan_text
from authzprobe.http import Response
from authzprobe.jwtutil import mint

ANON = mint("s", {"role": "anon", "ref": "abcd"})
SERVICE = mint("s", {"role": "service_role"})


def test_scan_text_finds_url_key_tables_rpcs_buckets():
    js = (f'const s=createClient("https://abcdefghijklmnop.supabase.co","{ANON}");'
          's.from("profiles").select();s.from(\'messages\').insert(x);s.rpc("get_stats");'
          's.storage.from("avatars").upload(a);Array.from(x);Buffer.from(y)')
    d = scan_text(js)
    assert d.supabase_url == "https://abcdefghijklmnop.supabase.co"
    assert d.anon_key == ANON
    assert d.tables == {"profiles", "messages"}
    assert d.rpcs == {"get_stats"}
    assert d.buckets == {"avatars"}
    assert not d.service_keys


def test_scan_text_flags_service_key_and_new_keys():
    d = scan_text(f'x="{SERVICE}";y="sb_publishable_AbCdEfGhIjKlMnOp";z="sb_secret_ZZZZZZZZZZZZZZZZ"')
    assert SERVICE in d.service_keys
    assert "sb_secret_ZZZZZZZZZZZZZZZZ" in d.service_keys
    assert "sb_publishable_AbCdEfGhIjKlMnOp" in d.anon_keys


def test_create_client_with_local_url():
    d = scan_text(f'createClient("http://127.0.0.1:54321/", "{ANON}")')
    assert d.supabase_url == "http://127.0.0.1:54321"


def test_discover_follows_same_origin_chunks_only():
    pages = {
        "https://app.example/": '<html><script type="module" src="/assets/index-1.js"></script>'
                                '<script src="https://cdn.evil/x.js"></script></html>',
        "https://app.example/assets/index-1.js": f'createClient("https://abcdefghijklmnop.supabase.co","{ANON}");'
                                                 'import("./Page-2.js");',
        "https://app.example/assets/Page-2.js": 'sb.from("orders").select()',
        "https://cdn.evil/x.js": 'sb.from("should_not_be_read")',
    }
    fetched = []

    def fetch(u):
        fetched.append(u)
        return Response(200, {}, pages[u].encode()) if u in pages else Response(404, {}, b"")

    d = discover("https://app.example/", fetch=fetch)
    assert d.tables == {"orders"}
    assert "https://cdn.evil/x.js" not in fetched
    assert len(d.files) == 2


def test_discover_raises_on_http_error():
    import pytest
    with pytest.raises(RuntimeError):
        discover("https://x/", fetch=lambda u: Response(500, {}, b""))
