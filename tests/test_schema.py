from authzprobe.schema import Resource, is_sensitive, parse_openapi

SPEC = {
    "paths": {"/": {}, "/profiles": {"get": {}, "patch": {}}, "/orders": {"get": {}, "post": {}},
              "/tags": {"get": {}}, "/rpc/stats": {"post": {}}},
    "definitions": {
        "profiles": {"required": ["id"], "properties": {
            "id": {"format": "uuid", "type": "string", "description": "Note:\nThis is a Primary Key.<pk/>"},
            "email": {"format": "text", "type": "string"}}},
        "orders": {"required": ["id", "user_id", "total"], "properties": {
            "id": {"format": "bigint", "type": "integer", "description": "<pk/>"},
            "user_id": {"format": "uuid", "type": "string"},
            "shop_id": {"format": "bigint", "type": "integer", "description": "<fk table='shops' column='id'/>"},
            "total": {"format": "numeric", "type": "number"},
            "note": {"format": "text", "type": "string"}}},
        "tags": {"properties": {"name": {"format": "text", "type": "string", "default": "x"}}},
    },
}


def test_parse_openapi_resources_and_rpcs():
    res, rpcs = parse_openapi(SPEC)
    assert set(res) == {"profiles", "orders", "tags"}
    assert rpcs == ["stats"]
    assert res["orders"].pk == "id"
    assert res["orders"].columns["shop_id"].fk == ("shops", "id")
    assert res["orders"].columns["total"].required
    assert res["tags"].columns["name"].has_default
    assert res["orders"].methods == {"get", "post"}


def test_owner_guess():
    res, _ = parse_openapi(SPEC)
    assert res["orders"].guess_owner() == "user_id"
    assert res["profiles"].guess_owner() == "id"   # profiles.id = auth.uid()
    assert res["tags"].guess_owner() is None
    assert res["tags"].guess_owner({"tags": "created_by"}) == "created_by"


def test_text_column_skips_owner_pk_fk():
    res, _ = parse_openapi(SPEC)
    r = res["orders"]
    r.guess_owner()
    assert r.text_column == "note"


def test_sensitive_names():
    for n in ("email", "phone_number", "passport_no", "home_address", "dob", "card", "content", "api_key"):
        assert is_sensitive(n), n
    for n in ("id", "title", "template", "related_id", "created_at", "status", "user_id"):
        assert not is_sensitive(n), n


def test_resource_without_columns():
    r = Resource("x")
    assert r.pk is None and r.text_column is None and r.guess_owner() is None
