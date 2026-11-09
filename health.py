"""域名到期（RDAP）与站点健康检查（HTTPS 状态码 / 响应时间 / HTTPS 跳转 / HSTS）。"""
import datetime as dt, ipaddress, logging, os, time
from urllib.parse import urljoin, urlsplit
import httpx
import netguard, db

log = logging.getLogger("health")
RDAP_BASE = os.getenv("RDAP_BASE", "https://rdap.org/domain/")
RDAP_TTL_OK = int(os.getenv("RDAP_TTL_OK_H", "24")) * 3600
RDAP_TTL_FAIL = int(os.getenv("RDAP_TTL_FAIL_H", "6")) * 3600
UA = "cert-checker/1.0 (+https://cert-checker-h6lr.onrender.com)"

def _parse_ts(s):
    try: return dt.datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(dt.timezone.utc)
    except Exception: return None

def candidates(domain):
    """可注册域名候选：先 3 段（兼容 co.uk 这类），再 2 段。"""
    p = domain.split(".")
    return [".".join(p[-n:]) for n in (3, 2) if len(p) >= n]

def _rdap_lookup(domain):
    """返回 dict(status=ok|unknown, registered_domain, expires, registrar, error)。不抛异常。"""
    last_err = "RDAP 无记录"
    for cand in candidates(domain):
        try:
            r = httpx.get(RDAP_BASE + cand, timeout=8, follow_redirects=True,
                          headers={"accept": "application/rdap+json", "user-agent": UA})
        except Exception as e:
            last_err = f"RDAP 查询失败：{type(e).__name__}"; continue
        if r.status_code == 404: continue
        if r.status_code != 200: last_err = f"RDAP 返回 {r.status_code}"; continue
        try: j = r.json()
        except Exception: last_err = "RDAP 响应无法解析"; continue
        exp = next((e.get("eventDate") for e in j.get("events", []) if e.get("eventAction") == "expiration"), None)
        registrar = None
        for ent in j.get("entities", []) or []:
            if "registrar" in (ent.get("roles") or []):
                for f in (ent.get("vcardArray") or [None, []])[1]:
                    if f and f[0] == "fn": registrar = f[3]
        if not exp: return {"status": "unknown", "registered_domain": cand, "expires": None, "registrar": registrar, "error": "注册局未公开到期时间"}
        return {"status": "ok", "registered_domain": cand, "expires": exp, "registrar": registrar, "error": None}
    return {"status": "unknown", "registered_domain": None, "expires": None, "registrar": None, "error": last_err}

def domain_expiry(domain, use_cache=True):
    """带数据库缓存的域名到期查询，结果附 days_left。"""
    row = None
    if use_cache:
        try: row = db.cache_get(domain)
        except Exception as e: log.warning("读取 RDAP 缓存失败：%s", e)
    res = None
    if row and row.get("rdap_checked_at"):
        age = (dt.datetime.now(dt.timezone.utc) - _parse_ts(row["rdap_checked_at"])).total_seconds()
        ttl = RDAP_TTL_OK if row.get("rdap_status") == "ok" else RDAP_TTL_FAIL
        if age < ttl:
            res = {"status": row["rdap_status"], "registered_domain": row.get("rdap_domain"), "expires": row.get("rdap_expires"),
                   "registrar": row.get("rdap_registrar"), "error": row.get("rdap_error"), "cached": True}
    if res is None:
        res = _rdap_lookup(domain); res["cached"] = False
        try: db.cache_put(domain, rdap_status=res["status"], rdap_domain=res["registered_domain"], rdap_expires=res["expires"],
                          rdap_registrar=res["registrar"], rdap_error=res["error"], rdap_checked_at=db.now())
        except Exception as e: log.warning("写入 RDAP 缓存失败：%s", e)
    exp = _parse_ts(res["expires"]) if res.get("expires") else None
    res["days_left"] = (exp - dt.datetime.now(dt.timezone.utc)).days if exp else None
    return res

# ---------------- 站点健康 ----------------
def _pinned_request(client, method, url):
    """对 URL 的主机做 SSRF 校验后，直连校验过的 IP（保留 Host / SNI），不跟随跳转。"""
    u = urlsplit(url)
    host = (u.hostname or "").lower()
    if u.scheme not in ("http", "https") or not host: raise netguard.Forbidden("不支持的跳转地址")
    if u.port not in (None, 80, 443): raise netguard.Forbidden("仅允许 80/443 端口")
    _, target = netguard.resolve_safe(host)
    if target != host:
        try: ipaddress.ip_address(target); netloc = f"[{target}]" if ":" in target else target
        except ValueError: netloc = target
        req_url = u._replace(netloc=netloc).geturl()
    else: req_url = url
    req = client.build_request(method, req_url, headers={"host": host, "user-agent": UA},
                               extensions={"sni_hostname": host} if u.scheme == "https" else {})
    return client.send(req, stream=True)

def site_health(domain, timeout=8, max_hops=5):
    out = {"url": f"https://{domain}/", "status": None, "final_url": None, "response_ms": None, "redirects": 0,
           "hsts": None, "https_redirect": None, "error": None}
    with httpx.Client(timeout=timeout, follow_redirects=False) as cl:
        url, t0 = out["url"], time.monotonic()
        try:
            for hop in range(max_hops + 1):
                r = _pinned_request(cl, "GET", url)
                try:
                    if hop == 0: out["hsts"] = "strict-transport-security" in r.headers  # 首个 HTTPS 响应
                    if r.is_redirect and r.headers.get("location") and hop < max_hops:
                        url = urljoin(url, r.headers["location"]); out["redirects"] += 1; continue
                    out["status"], out["final_url"] = r.status_code, url
                    break
                finally: r.close()
            out["response_ms"] = int((time.monotonic() - t0) * 1000)
        except netguard.Forbidden as e: out["error"] = str(e)
        except netguard.NXDomain: out["error"] = "跳转目标无法解析"
        except httpx.TimeoutException: out["error"] = f"HTTPS 请求超时（>{timeout}s）"
        except httpx.HTTPError as e: out["error"] = f"HTTPS 请求失败：{type(e).__name__}"
        # HTTP → HTTPS 跳转检查（只看第一跳）
        try:
            r = _pinned_request(cl, "GET", f"http://{domain}/")
            try:
                if r.is_redirect: out["https_redirect"] = urljoin(f"http://{domain}/", r.headers.get("location", "")).startswith("https://")
                elif r.status_code < 500: out["https_redirect"] = False   # 直接用 HTTP 提供内容
                # 5xx：未知
            finally: r.close()
        except Exception: out["https_redirect"] = None   # 80 端口不通等：未知
    return out

def issues(cert, dom, site):
    """返回 [(级别, 文案)]，级别 bad|warn|info。cert 可为 {'error':...}。"""
    out = []
    if not cert: pass
    elif cert.get("error"): out.append(("bad", f"证书检查失败：{cert['error']}"))
    else:
        d = cert["leaf"]["days_left"]
        if d < 0: out.append(("bad", f"证书已过期 {-d} 天"))
        elif d <= 14: out.append(("bad", f"证书 {d} 天后到期"))
        elif d <= 30: out.append(("warn", f"证书 {d} 天后到期"))
        if not cert.get("verified"): out.append(("bad", f"证书信任校验失败：{cert.get('verify_error')}"))
        if cert.get("exiting_ca"): out.append(("bad", "证书 CA 正在退出：" + "、".join(c["name"] for c in cert["exiting_ca"])))
    if dom and dom.get("days_left") is not None:
        d = dom["days_left"]
        if d < 0: out.append(("bad", f"域名已过期 {-d} 天"))
        elif d <= 30: out.append(("bad", f"域名 {d} 天后到期"))
        elif d <= 60: out.append(("warn", f"域名 {d} 天后到期"))
    if site:
        if site.get("error"): out.append(("bad", site["error"]))
        elif site.get("status") and site["status"] >= 400: out.append(("bad", f"首页返回 HTTP {site['status']}"))
        elif site.get("response_ms") and site["response_ms"] > 3000: out.append(("warn", f"首页响应慢（{site['response_ms']} ms）"))
        if site.get("https_redirect") is False: out.append(("warn", "HTTP 未自动跳转到 HTTPS"))
        if site.get("hsts") is False and not site.get("error"): out.append(("info", "未设置 HSTS 头"))
    return out
