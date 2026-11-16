"""仓库密钥扫描：全部 mock GitHub。假密钥运行时拼接，避免仓库里出现像真密钥的字符串。"""
import os, json
os.environ.setdefault("DB_PATH", "/tmp/certchk_test.db"); os.environ.setdefault("CRON_SECRET", "s3cret")
os.environ.setdefault("RATE_LIMIT_PER_MIN", "1000")
import httpx, pytest
from fastapi.testclient import TestClient
import app as A, db, mailer, repo_scan as R, repo_weekly

c = TestClient(A.app)
J = "".join
FAKE_GH = J(["gh", "p_"]) + "Ab3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6"          # 36 位
FAKE_ANT = J(["sk-", "ant-", "api03-"]) + "Xy7Q2mN9pL4kJ8hG3fD6sA1zW5vB0nM7qR2tY9uI4oP" + "AA"
FAKE_AWS = J(["AK", "IA"]) + "Z7Q2M9P4K8H3F6S1"
FAKE_GEN = "q8Zr2Lm9Xv4Tn7Kc3Wb6Yh1"
SECRETS = [FAKE_GH, FAKE_ANT, FAKE_AWS, FAKE_GEN]
PEM = J(["-----BEGIN ", "RSA PRIVATE KEY-----"]) + "\nMIIEow\n-----END RSA PRIVATE KEY-----\n"

FILES = {
    ".claude/settings.local.json": json.dumps({"env": {"ANTHROPIC_API_KEY": FAKE_ANT}}, indent=2),
    ".env": f"# config\nDEBUG=true\nGITHUB_TOKEN={FAKE_GH}\nAWS_ACCESS_KEY_ID={FAKE_AWS}\nSESSION_SECRET={FAKE_GEN}\nAPI_KEY=your_api_key_here\nPORT=8000\n",
    ".env.example": "OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxx\nTOKEN=changeme\n",
    "deploy/id_rsa": PEM,
    "src/main.py": "print('hi')\n",
    "README.md": f"token {FAKE_GH}\n",       # 非候选文件，不应扫描
}

@pytest.fixture(autouse=True)
def fresh(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_PATH", str(tmp_path / "t.db"))
    A.scan_limiter.hits.clear()

def mock_github(monkeypatch, files=FILES, meta=None, status=None, headers=None):
    calls = []
    def fake_get(url, headers_=None, **kw):
        calls.append(url)
        assert url.startswith(("https://api.github.com/", "https://raw.githubusercontent.com/")), url
        assert kw.get("follow_redirects") is False
        if status: return httpx.Response(status, headers=headers or {}, text="API rate limit exceeded")
        if url.endswith("/repos/acme/demo"):
            return httpx.Response(200, json=meta or {"full_name": "acme/demo", "private": False, "default_branch": "main"})
        if "/git/trees/HEAD" in url:
            return httpx.Response(200, json={"truncated": False, "tree": [{"path": p, "type": "blob", "size": len(t)} for p, t in files.items()]})
        if url.startswith("https://raw.githubusercontent.com/acme/demo/HEAD/"):
            p = url.split("/HEAD/", 1)[1].replace("%2F", "/")
            from urllib.parse import unquote
            return httpx.Response(200, text=files[unquote(p)])
        return httpx.Response(404)
    monkeypatch.setattr(R.httpx, "get", lambda url, headers=None, **kw: fake_get(url, headers, **kw))
    return calls

def test_parse_repo():
    for s in ["acme/demo", "https://github.com/Acme/Demo", "github.com/acme/demo.git", "https://github.com/acme/demo/tree/main/src", "git@github.com:acme/demo.git"]:
        assert R.parse_repo(s) == "acme/demo"
    for bad in ["", "acme", "https://gitlab.com/acme/demo", "http://169.254.169.254/latest", "evil.com/acme/demo", "../x/y", "acme/..", "a b/c"]:
        with pytest.raises(R.ScanError): R.parse_repo(bad)

def test_candidates():
    yes = [".env", "app/.env.local", ".env.production", ".claude/settings.local.json", ".cursor/mcp.json", "x/.cursor/rules/a.json",
           "credentials.json", "id_rsa", "certs/server.pem", ".mcp.json", ".npmrc"]
    no = ["src/main.py", "README.md", "node_modules/x/.env", "package.json"]
    assert all(R.is_candidate(p) for p in yes) and not any(R.is_candidate(p) for p in no)

def test_scan_detects_and_redacts(monkeypatch):
    calls = mock_github(monkeypatch)
    j = c.get("/api/repo-scan", params={"repo": "https://github.com/acme/demo"}).json()
    assert j["repo"] == "acme/demo" and j["files_scanned"] == 4 and j["level"] == "bad"
    types = {(f["path"], f["type"].split("（")[0]) for f in j["findings"] if not f["example"]}
    assert (".claude/settings.local.json", "Anthropic API Key") in types and (".env", "GitHub Token") in types
    assert (".env", "AWS Access Key") in types and (".env", "疑似密钥") in types and ("deploy/id_rsa", "私钥 Private key") in types
    env_lines = {f["line"] for f in j["findings"] if f["path"] == ".env"}
    assert env_lines == {3, 4, 5}                                 # 占位符 / DEBUG / PORT 不报
    assert all(f["example"] for f in j["findings"] if f["path"] == ".env.example")
    blob = json.dumps(j)
    for s in SECRETS: assert s not in blob and s[4:-2] not in blob    # 绝不返回完整密钥
    assert "MIIEow" not in blob and not any("README" in u for u in calls)
    assert j["advice"] and not j["cached"] and sum("api.github.com" in u for u in calls) == 1   # 每次扫描只用 1 次 API 额度
    # 缓存：第二次不再请求 GitHub
    n = len(calls); j2 = c.get("/api/repo-scan", params={"repo": "acme/demo"}).json()
    assert j2["cached"] and len(calls) == n
    assert all(s not in db.repo_cache_get("acme/demo")["result"] for s in SECRETS)   # 数据库里也只有脱敏结果

def test_clean_repo(monkeypatch):
    mock_github(monkeypatch, files={"src/a.py": "x=1", ".env.example": "API_KEY=\n"})
    j = c.get("/api/repo-scan", params={"repo": "acme/demo"}).json()
    assert j["level"] == "ok" and j["count"] == 0 and j["advice"] == []

def test_private_or_missing(monkeypatch):
    mock_github(monkeypatch, status=404)
    r = c.get("/api/repo-scan", params={"repo": "acme/secret"}); assert r.status_code == 404 and "公开" in r.json()["error"]
    monkeypatch.setenv("GITHUB_TOKEN", "t")       # 有 token 时会额外确认仓库公开
    calls = mock_github(monkeypatch, meta={"full_name": "acme/demo", "private": True, "default_branch": "main"})
    assert c.get("/api/repo-scan", params={"repo": "acme/demo"}).status_code == 403 and len(calls) == 1

def test_github_rate_limited(monkeypatch):
    mock_github(monkeypatch, status=403, headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "9999999999"})
    r = c.get("/api/repo-scan", params={"repo": "acme/demo"}); assert r.status_code == 429 and "额度" in r.json()["error"]
    mock_github(monkeypatch, status=429)
    assert c.get("/api/repo-scan", params={"repo": "acme/demo"}).status_code == 429

def test_scan_endpoint_rate_limit(monkeypatch):
    mock_github(monkeypatch, status=404)
    codes = [c.get("/api/repo-scan", params={"repo": f"acme/r{i}"}).status_code for i in range(6)]
    assert codes[:4] == [404] * 4 and codes[4] == 429

def test_non_github_rejected():
    r = c.get("/api/repo-scan", params={"repo": "https://example.com/a/b"}); assert r.status_code == 400

def test_redact():
    assert R.redact(FAKE_GH).startswith("ghp_") and FAKE_GH not in R.redact(FAKE_GH) and "40" in R.redact(FAKE_GH)
    assert "****" in R.redact("short12345")

def test_subscribe_and_weekly(monkeypatch):
    mock_github(monkeypatch)
    sent = []
    monkeypatch.setattr(mailer, "send", lambda to, s, b, html=None: sent.append((to, s, b, html)) or "id1")
    assert c.post("/api/repo/subscribe", json={"email": "u@x.com", "repo": "acme/demo"}).json()["error"].startswith("请先扫描")
    c.get("/api/repo-scan", params={"repo": "acme/demo"})
    j = c.post("/api/repo/subscribe", json={"email": "u@x.com", "repo": "github.com/acme/demo"}).json()
    assert j["ok"] and j["mail_sent"] and "repo/confirm?token=" in sent[0][2]
    tok = sent[0][2].split("token=")[1].split()[0]
    assert "已确认" in c.get("/api/repo/confirm", params={"token": tok}).text
    r = c.post("/api/cron/weekly", headers={"x-cron-secret": "s3cret"}).json()
    assert r["repos"]["sent"] == 1 and "***" in r["repos"]["results"][0]["to"]
    to, subj, text, html = sent[-1]
    assert to == "u@x.com" and "1 个发现疑似泄露" in subj and ".env:3" in text and "repo/unsubscribe" in text and "<ul" in html
    for s in SECRETS: assert s not in text and s not in html
    assert c.post("/api/cron/weekly", headers={"x-cron-secret": "s3cret"}).json()["repos"]["sent"] == 0
    utok = db.repo_subs_verified()[0]["unsub_token"]
    assert "已退订" in c.get("/api/repo/unsubscribe", params={"token": utok}).text and db.repo_subs_verified() == []

def test_subscribe_mail_failure_still_ok(monkeypatch):
    mock_github(monkeypatch); c.get("/api/repo-scan", params={"repo": "acme/demo"})
    monkeypatch.setattr(mailer, "send", lambda *a, **k: False)
    j = c.post("/api/repo/subscribe", json={"email": "u@x.com", "repo": "acme/demo"}).json()
    assert j["ok"] and j["mail_sent"] is False and "失败" in j["message"]

def test_weekly_scan_error(monkeypatch):
    mock_github(monkeypatch); c.get("/api/repo-scan", params={"repo": "acme/demo"})
    row, _ = db.repo_sub_add("u@x.com", "acme/demo"); db.repo_sub_confirm(row["confirm_token"])
    mock_github(monkeypatch, status=404)
    sent = []; monkeypatch.setattr(mailer, "send", lambda to, s, b, html=None: sent.append(b) or True)
    r = repo_weekly.run(); assert r["sent"] == 1 and "扫描失败" in sent[0]

def test_page():
    assert "仓库密钥泄露扫描" in c.get("/repo-check").text and "/repo-check" in c.get("/").text
