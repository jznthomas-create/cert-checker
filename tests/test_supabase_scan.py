"""Supabase 暴露扫描：全部 mock 网络，不访问任何真实 Supabase 项目。假 key 运行时生成。"""
import base64, json, os
os.environ.setdefault("DB_PATH", "/tmp/certchk_test.db"); os.environ.setdefault("CRON_SECRET", "s3cret")
os.environ.setdefault("RATE_LIMIT_PER_MIN", "1000")
import httpx, pytest
from fastapi.testclient import TestClient
import app as A, mailer, netguard, supabase_scan as S

c = TestClient(A.app)
REF = "abcdefghijklmnopqrst"
def b64(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
def jwt(role): return ".".join([b64({"alg": "HS256", "typ": "JWT"}), b64({"iss": "supabase", "ref": REF, "role": role, "iat": 1}), "S" * 20 + role + "x" * 20])
ANON, SERVICE = jwt("anon"), jwt("service_role")
PUB = "sb_" + "publishable_" + "Q" * 28
SECRET = "sb_" + "secret_" + "Z" * 28
FULL = [ANON, SERVICE, PUB, SECRET]

def site(pages):
    def fake(url, limit, client=None):
        if url not in pages: return {"status": 404, "url": url, "text": "", "truncated": False, "ctype": "text/html"}
        v = pages[url]
        if isinstance(v, tuple): return {"status": 200, "url": v[0], "text": v[1], "truncated": False, "ctype": ""}
        return {"status": 200, "url": url, "text": v, "truncated": False, "ctype": ""}
    return fake

HTML = '<html><head><script type="module" src="/assets/index-abc.js"></script><script src="https://cdn.other.com/x.js"></script>' \
       '<link rel="modulepreload" href="/assets/vendor.js"></head><body></body></html>'
JS = f'const u="https://{REF}.supabase.co";const k="{ANON}";import("./chunk-1.js")'

@pytest.fixture(autouse=True)
def fresh(monkeypatch):
    A.sb_limiter.hits.clear(); A.sb_mail_limiter.hits.clear()
    monkeypatch.setattr(S, "_dns_txt", lambda name: [])
    def no_real(*a, **k): raise AssertionError("不应访问真实网络")
    monkeypatch.setattr(S.httpx, "request", no_real)

def no_secrets(obj):
    s = json.dumps(obj, ensure_ascii=False)
    for k in FULL: assert k not in s, "完整 key 不应出现在输出中"

def test_parse_site():
    assert S.parse_site("https://My-App.lovable.app/path?x=1") == "my-app.lovable.app"
    assert S.parse_site("example.com:443") == "example.com"
    for bad in ["", "127.0.0.1", "http://[::1]/", "localhost", "ftp://a.com", "a.com:8080", "user@evil.com", f"{REF}.supabase.co"]:
        with pytest.raises(S.ScanError): S.parse_site(bad)

def test_find_keys_and_mask():
    acc = {"projects": set(), "keys": {}}
    S.find_keys(f"{JS} {SERVICE} {PUB} {SECRET} eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnopqrstuv", "x.js", acc)
    roles = sorted((i["kind"], i["role"]) for i in acc["keys"].values())
    assert roles == [("jwt", "anon"), ("jwt", "service_role"), ("publishable", "anon"), ("secret", "service_role")]
    assert acc["projects"] == {REF}
    no_secrets(list(acc["keys"].values()))

def test_passive_no_supabase(monkeypatch):
    monkeypatch.setattr(S, "fetch", site({"https://example.com/": "<html><script src='/app.js'></script></html>", "https://example.com/app.js": "console.log(1)"}))
    r = c.post("/api/supabase/scan", json={"site": "example.com"}).json()
    assert r["found_supabase"] is False and r["report"]["findings"] == [] and r["deep"] is False
    assert [s["path"] for s in r["passive"]["scripts"]] == ["/app.js"]

def test_passive_finds_keys_same_origin_only(monkeypatch):
    fetched = []
    pages = {"https://app.example.com/": HTML, "https://app.example.com/assets/index-abc.js": JS,
             "https://app.example.com/assets/vendor.js": f"x='{SERVICE}'", "https://app.example.com/assets/chunk-1.js": f"y='{PUB}'"}
    f = site(pages)
    monkeypatch.setattr(S, "fetch", lambda u, l, cl=None: (fetched.append(u), f(u, l))[1])
    r = c.post("/api/supabase/scan", json={"site": "https://app.example.com"}).json()
    assert not any("cdn.other.com" in u for u in fetched)
    assert "https://app.example.com/assets/chunk-1.js" in fetched   # 二级 chunk 发现
    assert r["passive"]["projects"] == [REF]
    assert r["report"]["summary"]["critical"] == 1 and "service_role" in r["report"]["findings"][0]["title"]
    assert r["report"]["advice"][0].startswith("立即")
    assert "_raw_keys" not in r["passive"]
    no_secrets(r)

def test_script_cap(monkeypatch):
    html = "".join(f'<script src="/s{i}.js"></script>' for i in range(60))
    pages = {"https://example.com/": html, **{f"https://example.com/s{i}.js": "1" for i in range(60)}}
    monkeypatch.setattr(S, "fetch", site(pages))
    r = S.scan("example.com")
    assert len(r["passive"]["scripts"]) == S.MAX_SCRIPTS and r["passive"]["notes"]

def test_ssrf_blocked(monkeypatch):
    def forbid(d): raise netguard.Forbidden("域名解析到非公网地址 10.0.0.1，已拒绝")
    monkeypatch.setattr(netguard, "resolve_safe", forbid)
    r = c.post("/api/supabase/scan", json={"site": "internal.example.com"})
    assert r.status_code == 403 and "非公网" in r.json()["error"]

def test_fetch_size_limit_and_redirect_check(monkeypatch):
    monkeypatch.setattr(netguard, "resolve_safe", lambda d: (["93.184.216.34"], "93.184.216.34"))
    def h(req):
        if req.headers["host"] == "example.com" and req.url.path == "/": return httpx.Response(302, headers={"location": "https://evil.internal/"})
        return httpx.Response(200, content=b"A" * 5000)
    with httpx.Client(transport=httpx.MockTransport(h)) as cl:
        r = S.fetch("https://example.com/big.js", 1000, cl)
        assert r["truncated"] and len(r["text"]) == 1000
        calls = []
        monkeypatch.setattr(netguard, "resolve_safe", lambda d: (calls.append(d), (_ for _ in ()).throw(netguard.Forbidden("x")) if d == "evil.internal" else (["93.184.216.34"], "93.184.216.34"))[1])
        with pytest.raises(netguard.Forbidden): S.fetch("https://example.com/", 1000, cl)
        assert calls == ["example.com", "evil.internal"]   # 每一跳都做 SSRF 校验

def test_deep_requires_verification(monkeypatch):
    pages = {"https://app.example.com/": HTML, "https://app.example.com/assets/index-abc.js": JS}
    monkeypatch.setattr(S, "fetch", site(pages))
    called = []
    monkeypatch.setattr(S, "deep_scan", lambda *a: called.append(a))
    r = c.post("/api/supabase/scan", json={"site": "app.example.com", "deep": True}).json()
    assert r["verification"]["ok"] is False and r["deep"] is False and not called
    assert len(r["verification"]["tried"]) == 3

def test_verification_methods(monkeypatch):
    host = "app.example.com"; t = S.verify_token(host)
    assert t == S.verify_token(host) and t != S.verify_token("other.example.com") and t.startswith("cc-verify-")
    monkeypatch.setattr(S, "fetch", site({f"https://{host}{S.VERIFY_FILE}": t + "\n", f"https://{host}/": ""}))
    assert S.check_ownership(host)[:2] == (True, "file")
    monkeypatch.setattr(S, "fetch", site({f"https://{host}/": f'<head><meta name="cert-checker-verify" content="{t}"></head>'}))
    assert S.check_ownership(host)[:2] == (True, "meta")
    monkeypatch.setattr(S, "fetch", site({f"https://{host}/": ""}))
    monkeypatch.setattr(S, "_dns_txt", lambda n: [t] if n == "_cert-checker-verify." + host else [])
    assert S.check_ownership(host)[:2] == (True, "dns")
    monkeypatch.setattr(S, "_dns_txt", lambda n: ["cc-verify-wrong"])
    assert S.check_ownership(host)[0] is False
    # 验证文件跳到别的域名不算
    monkeypatch.setattr(S, "fetch", site({f"https://{host}{S.VERIFY_FILE}": ("https://attacker.com/v.txt", t), f"https://{host}/": ""}))
    assert S.check_ownership(host)[0] is False

def test_cross_host_redirect_blocks_deep(monkeypatch):
    monkeypatch.setattr(S, "fetch", site({"https://mine.com/": ("https://victim.com/", HTML)}))
    monkeypatch.setattr(S, "check_ownership", lambda h, html=None: (True, "file", []))
    r = S.scan("mine.com", deep=True)
    assert r["verification"]["ok"] is False and "victim.com" in r["verification"]["error"] and not r["deep"]

def supabase_mock(monkeypatch, openapi_status=200):
    calls = []
    spec = {"paths": {"/": {}, "/profiles": {}, "/posts": {}, "/secrets_empty": {}, "/rpc/do_thing": {}},
            "definitions": {"profiles": {"properties": {"id": {}, "email": {}, "phone_number": {}, "avatar": {}}},
                            "posts": {"properties": {"id": {}, "title": {}}}, "secrets_empty": {"properties": {"api_token": {}}}}}
    def req(method, url, headers=None, **kw):
        calls.append((method, url, dict(headers)))
        assert method in ("GET", "HEAD") and kw.get("follow_redirects") is False
        assert url.startswith(f"https://{REF}.supabase.co/")
        assert headers["apikey"] == ANON
        p = url.split(".supabase.co", 1)[1]
        if p == "/rest/v1/": return httpx.Response(openapi_status, json=spec if openapi_status == 200 else {"message": "no"})
        if p.startswith("/rest/v1/profiles"):
            if method == "HEAD": return httpx.Response(200, headers={"content-range": "0-0/1234"})
            return httpx.Response(200, json=[{"id": 1, "email": "victim@example.com", "phone_number": "555", "avatar": "x"}])
        if p.startswith("/rest/v1/posts"):
            if method == "HEAD": return httpx.Response(200, headers={"content-range": "0-0/10"})
            return httpx.Response(200, json=[{"id": 1, "title": "hi"}])
        if p.startswith("/rest/v1/secrets_empty"):
            if method == "HEAD": return httpx.Response(200, headers={"content-range": "*/0"})
            return httpx.Response(200, json=[])
        if p == "/storage/v1/bucket": return httpx.Response(200, json=[{"id": "avatars", "name": "avatars", "public": True}, {"id": "docs", "name": "docs", "public": False}])
        return httpx.Response(404)
    monkeypatch.setattr(S.httpx, "request", req)
    return calls

def test_deep_scan_after_verification(monkeypatch):
    pages = {"https://app.example.com/": HTML, "https://app.example.com/assets/index-abc.js": JS}
    monkeypatch.setattr(S, "fetch", site(pages))
    monkeypatch.setattr(S, "check_ownership", lambda h, html=None: (True, "dns", []))
    calls = supabase_mock(monkeypatch)
    r = c.post("/api/supabase/scan", json={"site": "app.example.com", "deep": True}).json()
    assert r["deep"] and r["verification"]["ok"]
    t = {x["name"]: x for x in r["deep_result"]["tables"]}
    assert t["profiles"]["rows_visible"] and t["profiles"]["count"] == 1234 and set(t["profiles"]["pii_columns"]) == {"email", "phone_number"}
    assert t["posts"]["rows_visible"] and not t["posts"]["pii_columns"]
    assert t["secrets_empty"]["readable"] and not t["secrets_empty"]["rows_visible"]
    assert r["deep_result"]["rpc_count"] == 1
    assert not any("/rpc/" in u for _, u, _ in calls)          # 从不调用 RPC
    s = r["report"]["summary"]
    assert s["critical"] == 1 and s["high"] == 1 and s["medium"] == 1
    assert r["report"]["sql_example"] and "enable row level security" in r["report"]["sql_example"]
    out = json.dumps(r, ensure_ascii=False)
    assert "victim@example.com" not in out and "555" not in out and '"hi"' not in out   # 不泄露行数据
    no_secrets(r)

def test_deep_openapi_blocked(monkeypatch):
    monkeypatch.setattr(S, "fetch", site({"https://app.example.com/": HTML, "https://app.example.com/assets/index-abc.js": JS}))
    monkeypatch.setattr(S, "check_ownership", lambda h, html=None: (True, "file", []))
    supabase_mock(monkeypatch, openapi_status=401)
    r = S.scan("app.example.com", deep=True)
    assert r["deep_result"]["openapi"] == "blocked:401" and r["deep_result"]["tables"] == []

def test_sb_get_only_supabase():
    with pytest.raises(S.ScanError): S.sb_get("https://evil.com/rest/v1/", {})
    with pytest.raises(S.ScanError): S.sb_get("https://x.supabase.co.evil.com/", {})
    with pytest.raises(AssertionError): S.sb_get(f"https://{REF}.supabase.co/rest/v1/t", {}, "POST")

def test_rate_limit(monkeypatch):
    monkeypatch.setattr(S, "fetch", site({"https://example.com/": ""}))
    codes = [c.post("/api/supabase/scan", json={"site": "example.com"}).status_code for _ in range(A.sb_limiter.limit + 1)]
    assert codes[-1] == 429 and codes[0] == 200

def test_email_report(monkeypatch):
    monkeypatch.setattr(S, "fetch", site({"https://app.example.com/": HTML, "https://app.example.com/assets/index-abc.js": JS + f";'{SERVICE}'"}))
    rid = c.post("/api/supabase/scan", json={"site": "app.example.com"}).json()["report_id"]
    sent = []
    monkeypatch.setattr(mailer, "send", lambda to, sub, body, html=None: (sent.append(body), "id1")[1])
    r = c.post("/api/supabase/email", json={"email": "me@example.com", "report_id": rid})
    assert r.status_code == 200 and r.json()["mail_sent"]
    assert "CRITICAL" in sent[0] and not any(k in sent[0] for k in FULL)
    monkeypatch.setattr(mailer, "send", lambda *a, **k: False)
    r = c.post("/api/supabase/email", json={"email": "me@example.com", "report_id": rid})
    assert r.status_code == 503 and r.json()["mail_sent"] is False
    assert c.post("/api/supabase/email", json={"email": "me@example.com", "report_id": "nope"}).status_code == 404
    assert c.post("/api/supabase/email", json={"email": "bad", "report_id": rid}).status_code == 400

def test_token_and_page():
    r = c.post("/api/supabase/token", json={"site": "https://App.Example.com/x"}).json()
    assert r["host"] == "app.example.com" and r["token"] == S.verify_token("app.example.com") and len(r["methods"]) == 3
    p = c.get("/supabase-check"); assert p.status_code == 200 and "Supabase" in p.text
