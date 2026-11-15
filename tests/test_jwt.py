import time

from authzprobe.jwtutil import decode_unverified, is_jwt, key_role, mint, verify


def test_mint_and_verify_roundtrip():
    tok = mint("s3cret", {"role": "anon", "sub": "x"})
    assert verify("s3cret", tok)["role"] == "anon"
    assert verify("other", tok) is None


def test_expired_token_rejected():
    tok = mint("s", {"role": "anon"}, ttl=-10)
    assert verify("s", tok) is None


def test_decode_unverified_and_garbage():
    tok = mint("s", {"role": "service_role"})
    assert decode_unverified(tok)["role"] == "service_role"
    assert decode_unverified("nope") is None
    assert decode_unverified("a.b.c") is None
    assert not is_jwt("sb_publishable_abc")


def test_key_role_handles_new_and_legacy_keys():
    assert key_role("sb_publishable_abcdefghijklmnop") == "anon"
    assert key_role("sb_secret_abcdefghijklmnop") == "service_role"
    assert key_role(mint("s", {"role": "anon"})) == "anon"
    assert key_role(mint("s", {"role": "service_role"})) == "service_role"
    assert key_role("") is None
    assert key_role("random") is None


def test_iat_exp_set():
    p = decode_unverified(mint("s", {"role": "anon"}, ttl=60))
    assert p["exp"] - p["iat"] == 60 and abs(p["iat"] - time.time()) < 5
