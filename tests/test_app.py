import os, importlib, pytest
os.environ["DB_PATH"] = "/tmp/certchk_test.db"; os.environ["RATE_LIMIT_PER_MIN"] = "1000"
os.environ["DEV_EXPOSE_LINKS"] = "1"; os.environ["CRON_SECRET"] = "s3cret"
for k in ("RESEND_API_KEY", "SMTP_HOST"): os.environ.pop(k, None)
if os.path.exists("/tmp/certchk_test.db"): os.remove("/tmp/certchk_test.db")
from fastapi.testclient import TestClient
import app as A, netguard, ratelimit
c = TestClient(A.app)

def get(d): return c.get("/api/check", params={"domain": d})

@pytest.mark.parametrize("d,org", [("github.com", "Sectigo"), ("google.com", "Google Trust Services")])
def test_real(d, org):
    j = get(d).json(); assert org in j["leaf"]["issuer_org"] and j["verified"] and not j["exiting_ca"]

def test_emudhra():
    j = get("emsigner.com").json(); assert j["exiting_ca"][0]["name"] == "eMudhra" and len(j["migration_steps"]) >= 5

def test_expired():
    j = get("expired.badssl.com").json(); assert j["verified"] is False and j["leaf"]["days_left"] < 0

def test_nxdomain():
    r = get("nonexist-xyz-123-abc.com"); assert r.status_code == 400 and "无法解析域名" in r.json()["error"]

@pytest.mark.parametrize("d", ["127.0.0.1", "10.0.0.1", "[::1]", "169.254.169.254"])
def test_ip_literal(d): assert get(d).status_code == 400

@pytest.mark.parametrize("d", ["localtest.me", "10.0.0.1.nip.io", "169.254.169.254.nip.io", "192.168.1.1.sslip.io"])
def test_ssrf_private(d):
    r = get(d); assert r.status_code == 403 and "非公网" in r.json()["error"]

@pytest.mark.parametrize("d", ["github.com:22", "github.com:8443"])
def test_port(d): assert "443" in get(d).json()["error"]

def test_bad(): assert get("bad domain").status_code == 400

def test_is_public():
    for ip in ["127.0.0.1", "10.1.1.1", "172.16.0.1", "192.168.0.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fc00::1", "::ffff:127.0.0.1", "198.18.0.1", "224.0.0.1"]:
        assert not netguard.is_public(ip), ip
    assert netguard.is_public("140.82.116.4")

def test_ratelimit():
    rl = ratelimit.RateLimiter(limit=3); assert [rl.allow("a")[0] for _ in range(4)] == [True]*3 + [False]; assert rl.allow("b")[0]

def test_ratelimit_http(monkeypatch):
    monkeypatch.setattr(A, "limiter", ratelimit.RateLimiter(limit=2))
    codes = [get("bad domain").status_code for _ in range(3)]; assert codes == [400, 400, 429]

def test_subscription_flow(monkeypatch):
    sent = []; import mailer
    monkeypatch.setattr(mailer, "send", lambda to, s, b: sent.append((to, s, b)) or True)
    assert c.post("/api/subscribe", json={"email": "bad", "domain": "github.com"}).status_code == 400
    j = c.post("/api/subscribe", json={"email": "a@example.com", "domain": "emsigner.com"}).json()
    tok = j["confirm_url"].split("token=")[1]
    import check_expiry; assert check_expiry.run()["subscriptions"] == 0   # 未确认不提醒
    assert "已确认" in c.get("/api/confirm", params={"token": tok}).text
    assert c.post("/api/cron/run").status_code == 403
    r = c.post("/api/cron/run", headers={"x-cron-secret": "s3cret"}).json()
    assert r["sent"] == 1 and "eMudhra" in sent[-1][2]                    # 63 天 > 30，但 CA 退出触发提醒
    assert check_expiry.run()["sent"] == 0                                 # 不重复提醒
    import db; row = db.verified()[0]
    db.update(row["id"], last_serial="OLD", notified_thresholds="exitca")
    # 模拟到期临近
    real = A.inspect
    def fake(d): x = real(d); x["leaf"]["days_left"] = 5; return x
    monkeypatch.setattr(check_expiry, "inspect", fake)
    assert check_expiry.run()["sent"] == 1 and "5 天" in sent[-1][2]
    assert "已退订" in c.get("/api/unsubscribe", params={"token": row["unsub_token"]}).text
    assert db.verified() == []

def test_mailer_log_mode(caplog):
    import mailer; assert mailer.mode() == "log" and mailer.send("x@example.com", "t", "b")
