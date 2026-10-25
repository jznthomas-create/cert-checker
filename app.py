import json, re, socket, ssl, datetime as dt
from pathlib import Path
import httpx
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
import os, secrets as _secrets
from fastapi import FastAPI, Query, Request, Body
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse
import netguard, db, mailer
from ratelimit import RateLimiter

BASE = Path(__file__).parent
app = FastAPI(title="证书检查工具")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

def load_cas():
    return json.loads((BASE / "exiting_cas.json").read_text("utf-8"))["cas"]

def norm(raw: str):
    d = raw.strip().lower()
    d = re.sub(r"^[a-z]+://", "", d).split("/")[0].split("?")[0]
    port = 443
    if d.startswith("[") or d.count(":") > 1: raise ValueError("不允许直接输入 IP 地址")
    if ":" in d:
        d, p = d.rsplit(":", 1)
        if not p.isdigit(): raise ValueError("端口无效")
        port = int(p)
        if port != 443: raise ValueError("仅允许检查 443 端口")
    try: d = d.encode("idna").decode()
    except Exception: raise ValueError("域名格式无效")
    if not DOMAIN_RE.match(d): raise ValueError("域名格式无效")
    return d, port

def attr(name, oid):
    v = name.get_attributes_for_oid(oid)
    return v[0].value if v else None

def info(c: x509.Certificate):
    try:
        san = c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound: san = []
    nb, na = c.not_valid_before_utc, c.not_valid_after_utc
    return {
        "subject": c.subject.rfc4514_string(), "subject_cn": attr(c.subject, NameOID.COMMON_NAME),
        "issuer": c.issuer.rfc4514_string(), "issuer_org": attr(c.issuer, NameOID.ORGANIZATION_NAME),
        "issuer_cn": attr(c.issuer, NameOID.COMMON_NAME),
        "not_before": nb.isoformat(), "not_after": na.isoformat(),
        "days_left": (na - dt.datetime.now(dt.timezone.utc)).days,
        "serial": format(c.serial_number, "X"), "san": san[:50],
    }

def fetch(domain, port, timeout=8, target=None):
    verified, verr = True, None
    def go(ctx):
        with socket.create_connection((target or domain, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=domain) as ts:
                ch = ts.get_unverified_chain() or []
                return [x509.load_der_x509_certificate(ssl.PEM_cert_to_DER_cert(x) if isinstance(x, str) else (x.public_bytes(ssl.ENCODING_DER) if hasattr(x,'public_bytes') else x)) for x in ch], ts.version()
    try:
        return (*go(ssl.create_default_context()), True, None)
    except ssl.SSLCertVerificationError as e:
        verr = e.verify_message or str(e)
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        return (*go(ctx), False, verr)

def match_exit(chain):
    hits = []
    for ca in load_cas():
        for c in chain[:-1] or chain:  # 叶子和中间证书的颁发者
            text = " ".join(filter(None, [attr(c.issuer, NameOID.ORGANIZATION_NAME), attr(c.issuer, NameOID.COMMON_NAME)])).lower()
            if any(m.lower() in text for m in ca["match"]):
                hits.append(ca); break
    return hits

MIGRATION = [
    "盘点：列出所有使用该 CA 证书的域名/服务器/负载均衡/CDN，记录到期日（可用本工具或 crt.sh 查询）。",
    "选新 CA：免费自动化可选 Let's Encrypt、ZeroSSL、Google Trust Services；需要 OV/EV 或商业支持可选 DigiCert、Sectigo、GlobalSign 等。",
    "部署 ACME 自动化：如 certbot（certbot --nginx -d example.com）、acme.sh、Caddy 内置、Kubernetes cert-manager，实现 60–90 天自动续期。",
    "更新 DNS CAA 记录：加入新 CA（如 0 issue \"letsencrypt.org\"），并在迁移完成后移除旧 CA。",
    "在测试环境先签发并部署新证书，验证完整证书链、OCSP、客户端兼容性（老旧安卓/IoT/证书固定 pinning）。",
    "灰度替换生产证书并重载服务；更新任何固定了旧 CA 根/中间证书的客户端或信任库。",
    "上线后复检（本工具/SSL Labs），设置到期监控告警；在旧证书到期前完成全部切换并按需吊销旧证书。",
]

class CheckError(Exception):
    def __init__(self, msg, code=400): self.msg, self.code = msg, code

def inspect(raw):
    try: d, port = norm(raw)
    except ValueError as e: raise CheckError(str(e), 400)
    try: ips, target = netguard.resolve_safe(d)
    except netguard.NXDomain: raise CheckError(f"无法解析域名 {d}（DNS 无记录）", 400)
    except netguard.Forbidden as e: raise CheckError(str(e), 403)
    except Exception as e: raise CheckError(f"DNS 查询失败：{e}", 502)
    try:
        chain, ver, ok, verr = fetch(d, port, target=target)
    except socket.gaierror: raise CheckError(f"无法解析域名 {d}（DNS 无记录）", 400)
    except (socket.timeout, TimeoutError): raise CheckError(f"连接 {d}:{port} 超时", 504)
    except ConnectionRefusedError: raise CheckError(f"{d}:{port} 拒绝连接", 502)
    except ssl.SSLError as e: raise CheckError(f"TLS 握手失败：{e.reason or e}", 502)
    except OSError as e: raise CheckError(f"网络错误：{e.strerror or e}", 502)
    if not chain: raise CheckError("未获取到证书", 502)
    hits = match_exit(chain)
    return {"domain": d, "port": port, "ips": ips, "tls_version": ver, "verified": ok, "verify_error": verr,
            "leaf": info(chain[0]), "chain": [info(c) for c in chain],
            "exiting_ca": hits, "migration_steps": MIGRATION if hits else []}

limiter = RateLimiter()
def client_ip(req: Request):
    if os.getenv("TRUST_PROXY") == "1" and req.headers.get("x-forwarded-for"):
        return req.headers["x-forwarded-for"].split(",")[0].strip()
    return req.client.host if req.client else "unknown"

@app.middleware("http")
async def rate_limit(request: Request, call_next):
    if request.url.path.startswith("/api/") and not request.url.path.startswith("/api/cron"):
        ok, retry = limiter.allow(client_ip(request))
        if not ok:
            return JSONResponse({"error": f"请求过于频繁，请 {retry} 秒后再试"}, 429, headers={"Retry-After": str(retry)})
    return await call_next(request)

@app.get("/")
def index(): return FileResponse(BASE / "static" / "index.html")

@app.get("/api/check")
def check(domain: str = Query(...)):
    try: return inspect(domain)
    except CheckError as e: return JSONResponse({"error": e.msg}, e.code)

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[a-z0-9.-]+\.[a-z]{2,}$", re.I)
BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:8000")

@app.post("/api/subscribe")
def subscribe(payload: dict = Body(...)):
    email = str(payload.get("email", "")).strip().lower(); raw = str(payload.get("domain", ""))
    if not EMAIL_RE.match(email): return JSONResponse({"error": "邮箱格式无效"}, 400)
    try: d, _ = norm(raw); netguard.resolve_safe(d)
    except ValueError as e: return JSONResponse({"error": str(e)}, 400)
    except netguard.NXDomain: return JSONResponse({"error": f"无法解析域名 {raw}"}, 400)
    except netguard.Forbidden as e: return JSONResponse({"error": str(e)}, 403)
    try: row, created = db.add(email, d)
    except ValueError as e: return JSONResponse({"error": str(e)}, 400)
    if row["verified"]: return {"ok": True, "message": "已订阅该域名的到期提醒"}
    link = f"{BASE_URL}/api/confirm?token={row['confirm_token']}"
    mailer.send(email, f"请确认订阅 {d} 的证书到期提醒",
                f"你（或他人用你的邮箱）订阅了 {d} 的 TLS 证书到期提醒。\n确认订阅请打开：{link}\n如非本人操作，忽略本邮件即可。")
    resp = {"ok": True, "message": "确认邮件已发送，请点击邮件中的链接完成订阅"}
    if mailer.mode() == "log" and os.getenv("DEV_EXPOSE_LINKS") == "1": resp["confirm_url"] = link
    return resp

def page(msg): return HTMLResponse(f'<meta charset="utf-8"><body style="font-family:sans-serif;padding:40px"><h3>{msg}</h3><a href="/">返回</a></body>')

@app.get("/api/confirm")
def confirm(token: str):
    r = db.confirm(token)
    return page(f"✅ 已确认订阅 {r['domain']} 的到期提醒" if r else "链接无效或已使用")

@app.get("/api/unsubscribe")
def unsubscribe(token: str):
    r = db.unsubscribe(token)
    return page(f"已退订 {r['domain']}" if r else "链接无效或已退订")

@app.post("/api/cron/run")
def cron_run(request: Request):
    """供外部定时器（GitHub Actions / cron-job.org）调用的每日检查入口，需 CRON_SECRET。"""
    sec = os.getenv("CRON_SECRET")
    if not sec or not _secrets.compare_digest(request.headers.get("x-cron-secret", ""), sec):
        return JSONResponse({"error": "forbidden"}, 403)
    import check_expiry
    return check_expiry.run()

@app.get("/api/ct")
def ct(domain: str = Query(...)):
    try: d, _ = norm(domain)
    except ValueError as e: return JSONResponse({"error": str(e)}, 400)
    try:
        r = httpx.get("https://crt.sh/", params={"q": d, "output": "json", "exclude": "expired"}, timeout=25)
        r.raise_for_status(); rows = r.json()
    except httpx.TimeoutException: return JSONResponse({"error": "crt.sh 查询超时（该服务经常较慢，请稍后重试）"}, 504)
    except Exception as e: return JSONResponse({"error": f"crt.sh 查询失败：{e}"}, 502)
    rows.sort(key=lambda x: x.get("not_before", ""), reverse=True)
    return {"domain": d, "total": len(rows), "items": [{k: x.get(k) for k in ("id","issuer_name","common_name","name_value","not_before","not_after")} for x in rows[:30]]}

@app.get("/api/health")
def health():
    try: return {"ok": True, "storage": db.stats()}
    except Exception as e: return JSONResponse({"ok": False, "storage_backend": db.backend(), "error": type(e).__name__}, 500)
