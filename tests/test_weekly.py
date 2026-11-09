"""周报 / RDAP / 站点健康：全部 mock 网络。"""
import os, datetime as dt, sqlite3
os.environ.setdefault("DB_PATH", "/tmp/certchk_test.db"); os.environ.setdefault("CRON_SECRET", "s3cret")
os.environ.setdefault("RATE_LIMIT_PER_MIN", "1000")
import httpx, pytest
from fastapi.testclient import TestClient
import app as A, db, health, mailer, netguard, weekly

c = TestClient(A.app)
FUT = lambda d: (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=d, hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")

@pytest.fixture(autouse=True)
def fresh_db(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setattr(netguard, "resolve_safe", lambda d: (["93.184.216.34"], "93.184.216.34"))

def rdap_payload(exp, registrar="Example Registrar"):
    return {"events": [{"eventAction": "registration", "eventDate": "2000-01-01T00:00:00Z"}, {"eventAction": "expiration", "eventDate": exp}],
            "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", registrar]]]}]}

def test_candidates():
    assert health.candidates("www.example.co.uk") == ["example.co.uk", "co.uk"]
    assert health.candidates("www.github.com") == ["www.github.com", "github.com"]
    assert health.candidates("github.com") == ["github.com"]

def test_rdap_subdomain_fallback_and_cache(monkeypatch):
    calls = []
    def fake_get(url, **kw):
        calls.append(url)
        if url.endswith("/www.github.com"): return httpx.Response(404)
        return httpx.Response(200, json=rdap_payload(FUT(700), "MarkMonitor Inc."))
    monkeypatch.setattr(health.httpx, "get", fake_get)
    r = health.domain_expiry("www.github.com")
    assert r["status"] == "ok" and r["registered_domain"] == "github.com" and r["days_left"] == 700 and r["registrar"] == "MarkMonitor Inc."
    assert len(calls) == 2 and not r["cached"]
    r2 = health.domain_expiry("www.github.com")
    assert r2["cached"] and r2["days_left"] == 700 and len(calls) == 2     # 命中缓存，不再请求

def test_rdap_timeout_unknown(monkeypatch):
    def boom(url, **kw): raise httpx.ConnectTimeout("t")
    monkeypatch.setattr(health.httpx, "get", boom)
    r = health.domain_expiry("example.org")
    assert r["status"] == "unknown" and r["days_left"] is None and "ConnectTimeout" in r["error"]

def test_rdap_no_expiration(monkeypatch):
    monkeypatch.setattr(health.httpx, "get", lambda url, **kw: httpx.Response(200, json={"events": []}))
    r = health.domain_expiry("example.de"); assert r["status"] == "unknown" and r["days_left"] is None

def mock_site(monkeypatch, routes):
    """routes: url -> (status, headers) ；记录实际请求（检查 IP 直连 + Host/SNI）。"""
    seen = []
    def handler(req):
        host = req.headers["host"]; url = f"{req.url.scheme}://{host}{req.url.raw_path.decode()}"
        seen.append((str(req.url), host, req.extensions.get("sni_hostname")))
        st, hd = routes.get(url, (404, {}))
        if isinstance(st, Exception): raise st
        return httpx.Response(st, headers=hd)
    real = httpx.Client
    monkeypatch.setattr(health.httpx, "Client", lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    return seen

def test_site_health_ok(monkeypatch):
    seen = mock_site(monkeypatch, {
        "https://example.com/": (301, {"location": "https://www.example.com/", "strict-transport-security": "max-age=63072000"}),
        "https://www.example.com/": (200, {}),
        "http://example.com/": (301, {"location": "https://example.com/"})})
    h = health.site_health("example.com")
    assert h["status"] == 200 and h["final_url"] == "https://www.example.com/" and h["redirects"] == 1
    assert h["hsts"] is True and h["https_redirect"] is True and h["error"] is None and h["response_ms"] >= 0
    assert seen[0][0].startswith("https://93.184.216.34/") and seen[0][1:] == ("example.com", "example.com")
    assert health.issues({}, {"days_left": 400}, h) == []

def test_site_health_problems(monkeypatch):
    mock_site(monkeypatch, {"https://example.com/": (503, {}), "http://example.com/": (200, {})})
    h = health.site_health("example.com")
    assert h["status"] == 503 and h["hsts"] is False and h["https_redirect"] is False
    msgs = [m for _, m in health.issues({}, {"days_left": 20}, h)]
    assert any("503" in m for m in msgs) and any("域名 20 天" in m for m in msgs) and any("HTTPS" in m for m in msgs)

def test_site_health_timeout(monkeypatch):
    mock_site(monkeypatch, {"https://example.com/": (httpx.ReadTimeout("x"), {}), "http://example.com/": (500, {})})
    h = health.site_health("example.com")
    assert "超时" in h["error"] and h["https_redirect"] is None and h["status"] is None

def test_redirect_to_private_blocked(monkeypatch):
    def rs(d):
        if d == "evil.example.com": raise netguard.Forbidden("域名解析到非公网地址 10.0.0.1，已拒绝")
        return ["93.184.216.34"], "93.184.216.34"
    monkeypatch.setattr(netguard, "resolve_safe", rs)
    mock_site(monkeypatch, {"https://example.com/": (302, {"location": "https://evil.example.com/admin"})})
    h = health.site_health("example.com"); assert "非公网" in h["error"]

def test_redirect_bad_port_blocked(monkeypatch):
    mock_site(monkeypatch, {"https://example.com/": (302, {"location": "https://example.com:6379/"})})
    assert "端口" in health.site_health("example.com")["error"]

def test_issues_cert():
    cert = {"leaf": {"days_left": 5}, "verified": False, "verify_error": "self signed", "exiting_ca": [{"name": "eMudhra"}]}
    lv = health.issues(cert, {"days_left": None}, None)
    assert [l for l, _ in lv] == ["bad", "bad", "bad"]

def test_migration_additive(tmp_path, monkeypatch):
    """旧库（无 last_digest_at / domain_cache）升级后数据不丢。"""
    p = tmp_path / "old.db"; monkeypatch.setenv("DB_PATH", str(p))
    con = sqlite3.connect(p); con.execute(f"CREATE TABLE subscriptions(id INTEGER PRIMARY KEY, {db.COLS})")
    con.execute("INSERT INTO subscriptions(email,domain,verified,unsub_token) VALUES('a@x.com','x.com',1,'tok')"); con.commit(); con.close()
    rows = db.verified(); assert rows[0]["email"] == "a@x.com" and "last_digest_at" in rows[0]
    db.cache_put("x.com", rdap_status="ok", rdap_expires="2030-01-01T00:00:00Z"); db.cache_put("x.com", rdap_status="unknown")
    assert db.cache_get("x.com")["rdap_status"] == "unknown"

def fake_check(d):
    cert = {"leaf": {"days_left": 10 if d == "bad.com" else 80, "issuer_org": "Let's Encrypt"}, "verified": True, "exiting_ca": []}
    dom = {"days_left": 300, "status": "ok"}
    site = {"status": 200, "response_ms": 120, "hsts": True, "https_redirect": True, "error": None}
    return {"domain": d, "cert": cert, "dom": dom, "site": site, "issues": health.issues(cert, dom, site)}

def test_weekly_digest(monkeypatch):
    sent = []
    monkeypatch.setattr(weekly, "check_domain", fake_check)
    monkeypatch.setattr(mailer, "send", lambda to, s, b, html=None: sent.append((to, s, b, html)) or "msg_123")
    for e, d in [("u@x.com", "good.com"), ("u@x.com", "bad.com"), ("v@x.com", "good.com"), ("w@x.com", "nover.com")]:
        row, _ = db.add(e, d)
        if d != "nover.com": db.confirm(row["confirm_token"])
    assert c.post("/api/cron/weekly").status_code == 403
    r = c.post("/api/cron/weekly", headers={"x-cron-secret": "s3cret"}).json()
    assert r["emails"] == 2 and r["domains"] == 2 and r["sent"] == 2      # 每个邮箱一封，未确认的不发
    assert all("@" in x["to"] and "***" in x["to"] for x in r["results"]) and r["results"][0]["id"] == "msg_123"
    u = next(x for x in sent if x[0] == "u@x.com")
    assert "1 个需处理" in u[1] and "good.com" in u[2] and "bad.com" in u[2] and "证书 10 天后到期" in u[2]
    assert "Weekly" in u[2] and "unsubscribe-all" in u[2] and "<table" in u[3] and "#dc2626" in u[3]
    assert c.post("/api/cron/weekly", headers={"x-cron-secret": "s3cret"}).json()["sent"] == 0   # 6 天内不重复
    assert c.post("/api/cron/weekly?force=1", headers={"x-cron-secret": "s3cret"}).json()["sent"] == 2
    tok = db.verified()[0]["unsub_token"]
    assert "全部 2 个" in c.get("/api/unsubscribe-all", params={"token": tok}).text
    assert {s["email"] for s in db.verified()} == {"v@x.com"}

def test_weekly_send_failure(monkeypatch):
    monkeypatch.setattr(weekly, "check_domain", fake_check)
    def fail(*a, **k): mailer.last_error = "Resend 403: testing"; return False
    monkeypatch.setattr(mailer, "send", fail)
    row, _ = db.add("u@x.com", "good.com"); db.confirm(row["confirm_token"])
    r = weekly.run(); assert r["sent"] == 0 and "403" in r["results"][0]["error"]
    assert db.verified()[0]["last_digest_at"] is None                   # 失败不记为已发送

def test_api_site(monkeypatch):
    monkeypatch.setattr(health, "domain_expiry", lambda d: {"days_left": 25, "status": "ok", "expires": FUT(25)})
    monkeypatch.setattr(health, "site_health", lambda d: {"status": 200, "response_ms": 50, "hsts": False, "https_redirect": True, "error": None})
    j = c.get("/api/site", params={"domain": "Example.com"}).json()
    assert j["domain"] == "example.com" and j["domain_expiry"]["days_left"] == 25 and any("域名 25 天" in m for _, m in j["issues"])
    assert c.get("/api/site", params={"domain": "10.0.0.1"}).status_code == 400

def test_mailer_resend_id(monkeypatch):
    monkeypatch.setenv("RESEND_API_KEY", "re_test")
    monkeypatch.setattr(mailer.httpx, "post", lambda *a, **k: httpx.Response(200, json={"id": "abc"}))
    assert mailer.send("a@x.com", "s", "b", html="<b>b</b>") == "abc"
    monkeypatch.setattr(mailer.httpx, "post", lambda *a, **k: httpx.Response(403, json={"message": "only own email"}))
    assert mailer.send("a@x.com", "s", "b") is False and "403" in mailer.last_error

def test_admin_confirm():
    db.add("o@x.com", "a.com"); db.add("o@x.com", "b.com")
    assert c.post("/api/cron/admin-confirm", json={"email": "o@x.com"}).status_code == 403
    assert c.post("/api/cron/admin-confirm", json={"email": "o@x.com"}, headers={"x-cron-secret": "s3cret"}).json()["confirmed"] == 2
    assert len(db.verified()) == 2
