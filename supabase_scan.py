"""vibe-coded 应用（Lovable / Bolt / v0 等）Supabase 数据暴露扫描。

两级：
  1) 被动扫描（任何人可用）：抓取首页 + 同源 JS（大小/数量上限，SSRF 防护），
     识别 Supabase 项目地址、anon / publishable key，以及误暴露的 service_role / sb_secret_ key。
  2) 深度扫描（必须先验证站点所有权）：用页面里公开的 anon key 做只读探测：
     OpenAPI 列出暴露的表 → 每张表 GET limit=1 判断能否匿名读取 → HEAD 计数 → 标记疑似 PII 列；
     列出 storage bucket。绝不写入（无 INSERT/UPDATE/DELETE/RPC/注册），绝不返回行数据。

安全约定：任何位置都不返回、不保存、不记录完整密钥，只保留脱敏预览。
"""
import base64, hashlib, hmac, json, os, re, secrets, time, threading
from urllib.parse import urljoin, urlsplit, quote
import httpx
import netguard, health

UA = "cert-checker-supabase-scan/1.0 (+https://cert-checker-h6lr.onrender.com/supabase-check)"
MAX_HTML = 1_500_000
MAX_JS = 3_000_000
MAX_TOTAL = 12_000_000
MAX_SCRIPTS = int(os.getenv("SB_MAX_SCRIPTS", "25"))
MAX_TABLES = int(os.getenv("SB_MAX_TABLES", "30"))
DEADLINE = float(os.getenv("SB_DEADLINE_S", "45"))
TIMEOUT = 8
VERIFY_FILE = "/.well-known/cert-checker-verify.txt"
VERIFY_META = "cert-checker-verify"
VERIFY_DNS_PREFIX = "_cert-checker-verify."
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

class ScanError(Exception):
    def __init__(self, msg, code=400): super().__init__(msg); self.msg, self.code = msg, code

# ---------- 输入 ----------
def parse_site(raw: str) -> str:
    s = (raw or "").strip().lower()
    if not s: raise ScanError("请输入你的网站地址")
    if re.match(r"^[a-z][a-z0-9+.-]*://", s) and not s.startswith(("http://", "https://")): raise ScanError("只支持 http(s) 网站")
    s = re.sub(r"^https?://", "", s).split("/")[0].split("?")[0].split("#")[0]
    if "@" in s: raise ScanError("网址格式无效")
    if s.startswith("[") or s.count(":") > 1: raise ScanError("不允许直接输入 IP 地址")
    if ":" in s:
        s, p = s.rsplit(":", 1)
        if p != "443": raise ScanError("仅支持 443 端口的 HTTPS 网站")
    try: s = s.encode("idna").decode()
    except Exception: raise ScanError("域名格式无效")
    if not DOMAIN_RE.match(s): raise ScanError("域名格式无效")
    if s.endswith(".supabase.co"): raise ScanError("请输入你的前端网站地址，而不是 Supabase 项目地址")
    return s

# ---------- 脱敏 ----------
def mask(v: str) -> str:
    v = v or ""
    if len(v) <= 12: return v[:2] + "****"
    return f"{v[:6]}…{v[-4:]}（共 {len(v)} 位）"

def _b64json(seg):
    try: return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
    except Exception: return None

# ---------- 识别 ----------
SB_URL_RE = re.compile(r"https?://([a-z0-9]{20})\.supabase\.(?:co|in)\b", re.I)
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}")
PUB_RE = re.compile(r"\bsb_publishable_[A-Za-z0-9_-]{16,}")
SECRET_RE = re.compile(r"\bsb_secret_[A-Za-z0-9_-]{16,}")
SCRIPT_RE = re.compile(r"<script\b[^>]*?\bsrc\s*=\s*[\"']([^\"'>]+)[\"']", re.I)
PRELOAD_RE = re.compile(r"<link\b[^>]*?\brel\s*=\s*[\"']?(?:modulepreload|preload)[\"']?[^>]*?\bhref\s*=\s*[\"']([^\"'>]+\.m?js[^\"'>]*)[\"']", re.I)
PRELOAD_RE2 = re.compile(r"<link\b[^>]*?\bhref\s*=\s*[\"']([^\"'>]+\.m?js[^\"'>]*)[\"'][^>]*?\brel\s*=\s*[\"']?(?:modulepreload|preload)", re.I)
INLINE_RE = re.compile(r"<script\b(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script>", re.I | re.S)
CHUNK_RE = re.compile(r"[\"'`](\.{0,2}/?(?:assets|_next/static/chunks|static/js|_nuxt|build)/[A-Za-z0-9_./-]{1,160}\.m?js)[\"'`]")
CHUNK_REL_RE = re.compile(r"[\"'`](\./[A-Za-z0-9_.-]{1,120}\.m?js)[\"'`]")
META_RE = re.compile(r"<meta\b[^>]*>", re.I)

def find_keys(text: str, where: str, acc: dict):
    """把发现合并进 acc：{'projects': set, 'keys': {raw: info}}。info 里只有脱敏信息；raw 只在内存里用于深度扫描。"""
    for m in SB_URL_RE.finditer(text): acc["projects"].add(m.group(1).lower())
    for m in JWT_RE.finditer(text):
        tok = m.group(0); p = _b64json(tok.split(".")[1]) or {}
        role = p.get("role")
        if role not in ("anon", "service_role") and p.get("iss") != "supabase": continue
        if role not in ("anon", "service_role"): role = str(role or "unknown")[:20]
        ref = str(p.get("ref") or "")[:40].lower()
        if ref and re.fullmatch(r"[a-z0-9]{20}", ref): acc["projects"].add(ref)
        acc["keys"].setdefault(tok, {"kind": "jwt", "role": role, "ref": ref or None, "preview": mask(tok), "where": where})
    for m in PUB_RE.finditer(text):
        acc["keys"].setdefault(m.group(0), {"kind": "publishable", "role": "anon", "ref": None, "preview": mask(m.group(0)), "where": where})
    for m in SECRET_RE.finditer(text):
        acc["keys"].setdefault(m.group(0), {"kind": "secret", "role": "service_role", "ref": None, "preview": mask(m.group(0)), "where": where})

# ---------- 抓取（SSRF 防护 + 上限） ----------
def _read_limited(r, limit):
    buf = bytearray()
    for chunk in r.iter_bytes():
        buf += chunk
        if len(buf) > limit: return bytes(buf[:limit]), True
    return bytes(buf), False

def fetch(url, limit, client=None):
    """GET 公网 URL（逐跳 SSRF 校验，最多 3 跳）。返回 dict(status, url, text, truncated, ctype)。"""
    own = client is None
    cl = client or httpx.Client(timeout=TIMEOUT, follow_redirects=False)
    try:
        for hop in range(4):
            r = health._pinned_request(cl, "GET", url)
            try:
                if r.is_redirect and r.headers.get("location") and hop < 3:
                    url = urljoin(url, r.headers["location"]); continue
                body, trunc = _read_limited(r, limit)
                return {"status": r.status_code, "url": url, "text": body.decode("utf-8", "replace"),
                        "truncated": trunc, "ctype": r.headers.get("content-type", "")}
            finally: r.close()
        raise ScanError("跳转次数过多", 502)
    finally:
        if own: cl.close()

def _host(url): return (urlsplit(url).hostname or "").lower()

def same_site(a, b):
    a, b = a.removeprefix("www."), b.removeprefix("www.")
    return a == b

def passive_scan(host: str):
    t0 = time.monotonic()
    acc = {"projects": set(), "keys": {}}
    scripts_out, notes = [], []
    with httpx.Client(timeout=TIMEOUT, follow_redirects=False) as cl:
        try: page = fetch(f"https://{host}/", MAX_HTML, cl)
        except netguard.Forbidden as e: raise ScanError(str(e), 403)
        except netguard.NXDomain: raise ScanError(f"无法解析域名 {host}", 400)
        except httpx.TimeoutException: raise ScanError("打开网站超时", 504)
        except httpx.HTTPError as e: raise ScanError(f"打开网站失败：{type(e).__name__}", 502)
        final_host = _host(page["url"])
        if page["status"] != 200: notes.append(f"首页返回 HTTP {page['status']}（可能被防火墙/机器人防护拦截），结果可能不完整")
        html = page["text"]
        for i, m in enumerate(INLINE_RE.finditer(html)): find_keys(m.group(1), "首页内联脚本", acc)
        queue, seen = [], set()
        def add(src, base):
            src = src.strip()
            if src.startswith(("assets/", "_next/", "static/", "_nuxt/", "build/")): src = "/" + src   # 打包器写的根相对路径
            u = urljoin(base, src)
            us = urlsplit(u)
            if us.scheme != "https" or _host(u) != final_host: return
            u = us._replace(fragment="").geturl()
            if u not in seen: seen.add(u); queue.append(u)
        for rx in (SCRIPT_RE, PRELOAD_RE, PRELOAD_RE2):
            for m in rx.finditer(html): add(m.group(1), page["url"])
        total = len(html.encode())
        while queue and len(scripts_out) < MAX_SCRIPTS:
            if time.monotonic() - t0 > DEADLINE: notes.append("扫描超时，部分脚本未检查"); break
            if total > MAX_TOTAL: notes.append("脚本总量超出上限，部分脚本未检查"); break
            u = queue.pop(0)
            try: js = fetch(u, MAX_JS, cl)
            except Exception as e:
                scripts_out.append({"path": urlsplit(u).path, "error": type(e).__name__}); continue
            if _host(js["url"]) != final_host:
                scripts_out.append({"path": urlsplit(u).path, "error": "跳转到其他域名，已跳过"}); continue
            total += len(js["text"]); path = urlsplit(u).path
            scripts_out.append({"path": path, "status": js["status"], "bytes": len(js["text"]), "truncated": js["truncated"]})
            if js["status"] != 200: continue
            find_keys(js["text"], path, acc)
            for rx in (CHUNK_RE, CHUNK_REL_RE):
                for m in rx.finditer(js["text"]): add(m.group(1), u)
        if queue: notes.append(f"还有 {len(queue)} 个脚本超出数量上限未检查")
    keys = list(acc["keys"].values())
    return {"host": host, "final_host": final_host, "status": page["status"],
            "projects": sorted(acc["projects"]), "keys": keys, "scripts": scripts_out, "notes": notes,
            "_raw_keys": list(acc["keys"].items())}   # 仅供内部深度扫描使用，返回前必须删除

# ---------- 所有权验证 ----------
def _secret():
    return (os.getenv("VERIFY_SECRET") or os.getenv("CRON_SECRET") or "dev-only-secret").encode()

def verify_token(host: str) -> str:
    return "cc-verify-" + hmac.new(_secret(), host.encode(), hashlib.sha256).hexdigest()[:32]

def instructions(host):
    t = verify_token(host)
    return {"host": host, "token": t, "methods": [
        {"type": "file", "title": "上传文件", "url": f"https://{host}{VERIFY_FILE}", "content": t},
        {"type": "meta", "title": "首页 meta 标签", "content": f'<meta name="{VERIFY_META}" content="{t}">'},
        {"type": "dns", "title": "DNS TXT 记录", "name": f"{VERIFY_DNS_PREFIX}{host}", "content": t},
    ]}

def _dns_txt(name):
    try:
        r = httpx.get(netguard.DOH_URL, params={"name": name, "type": "TXT"}, headers={"accept": "application/dns-json"}, timeout=6)
        return [a.get("data", "").replace('" "', "").strip('"') for a in r.json().get("Answer", []) if a.get("type") == 16]
    except Exception: return []

def _meta_has(html, token):
    for m in META_RE.finditer(html or ""):
        tag = m.group(0)
        if re.search(rf"name\s*=\s*[\"']?{VERIFY_META}[\"']?", tag, re.I) and token in tag: return True
    return False

def check_ownership(host: str, html: str | None = None):
    """返回 (ok, method, tried)。依次检查文件 / meta / DNS。"""
    t = verify_token(host); tried = []
    try:
        r = fetch(f"https://{host}{VERIFY_FILE}", 4096)
        if r["status"] == 200 and same_site(_host(r["url"]), host) and t in r["text"]: return True, "file", tried
        tried.append(f"文件：HTTP {r['status']}" + ("" if r["status"] != 200 else "，内容不匹配"))
    except Exception as e: tried.append(f"文件：{type(e).__name__}")
    if html is None:
        try: html = fetch(f"https://{host}/", MAX_HTML)["text"]
        except Exception: html = ""
    if _meta_has(html, t): return True, "meta", tried
    tried.append("meta：未找到")
    for name in (VERIFY_DNS_PREFIX + host, host):
        if any(t in v for v in _dns_txt(name)): return True, "dns", tried
    tried.append("DNS TXT：未找到")
    return False, None, tried

# ---------- 深度只读探测 ----------
PII_RE = re.compile(r"e-?mail|phone|mobile|tel\b|password|passwd|pwd|secret|token|api_?key|address|addr|street|zip|postal|"
                    r"ssn|id_?card|passport|birth|dob|salary|iban|card|cvv|ip_?addr|first_?name|last_?name|full_?name|wechat|身份证|手机|邮箱|地址", re.I)

def sb_get(url, headers, method="GET"):
    """仅允许 GET/HEAD，且只发往 <ref>.supabase.co。"""
    assert method in ("GET", "HEAD")
    h = urlsplit(url)
    if h.scheme != "https" or not re.fullmatch(r"[a-z0-9]{20}\.supabase\.co", h.hostname or ""): raise ScanError("非法探测地址", 400)
    return httpx.request(method, url, headers={**headers, "user-agent": UA}, timeout=TIMEOUT, follow_redirects=False)

def _auth_headers(key):
    h = {"apikey": key}
    if key.startswith("eyJ"): h["authorization"] = f"Bearer {key}"
    return h

def _count(cr):
    # Content-Range: 0-0/123 或 */0
    try: return int(cr.rsplit("/", 1)[1])
    except Exception: return None

def deep_scan(ref: str, key: str):
    base = f"https://{ref}.supabase.co"
    H = _auth_headers(key); t0 = time.monotonic()
    out = {"project": ref, "openapi": None, "tables": [], "rpc_count": 0, "buckets": None, "notes": []}
    try:
        r = sb_get(base + "/rest/v1/", {**H, "accept": "application/openapi+json"})
    except httpx.HTTPError as e:
        out["openapi"] = f"error:{type(e).__name__}"; return out
    if r.status_code != 200:
        out["openapi"] = f"blocked:{r.status_code}"
        out["notes"].append(f"匿名 key 无法读取 OpenAPI 表结构（HTTP {r.status_code}），无法枚举表名")
    else:
        try: spec = r.json()
        except Exception: spec = {}
        paths = spec.get("paths") or {}
        defs = spec.get("definitions") or {}
        names = [p[1:] for p in paths if p.startswith("/") and p != "/" and not p.startswith("/rpc/")]
        out["rpc_count"] = sum(1 for p in paths if p.startswith("/rpc/"))
        out["openapi"] = "exposed"; out["table_total"] = len(names)
        if len(names) > MAX_TABLES: out["notes"].append(f"共 {len(names)} 张表/视图，只检查前 {MAX_TABLES} 张")
        for name in names[:MAX_TABLES]:
            if time.monotonic() - t0 > DEADLINE: out["notes"].append("探测超时，部分表未检查"); break
            cols = list(((defs.get(name) or {}).get("properties") or {}).keys())
            t = {"name": name[:120], "columns": [c[:80] for c in cols[:80]], "readable": False, "rows_visible": False,
                 "count": None, "status": None}
            u = f"{base}/rest/v1/{quote(name, safe='')}"
            try:
                g = sb_get(u + "?select=*&limit=1", H)
                t["status"] = g.status_code
                if g.status_code == 200:
                    t["readable"] = True
                    try: rows = g.json()
                    except Exception: rows = []
                    if isinstance(rows, list) and rows:
                        t["rows_visible"] = True
                        if isinstance(rows[0], dict) and not t["columns"]: t["columns"] = [k[:80] for k in list(rows[0].keys())[:80]]
                    del rows   # 不保留任何行数据
                    try:
                        hd = sb_get(u + "?select=*", {**H, "prefer": "count=exact", "range-unit": "items", "range": "0-0"}, "HEAD")
                        t["count"] = _count(hd.headers.get("content-range", ""))
                    except httpx.HTTPError: pass
            except httpx.HTTPError as e: t["status"] = type(e).__name__
            t["pii_columns"] = [c for c in t["columns"] if PII_RE.search(c)]
            out["tables"].append(t)
    try:
        b = sb_get(base + "/storage/v1/bucket", H)
        if b.status_code == 200 and isinstance(b.json(), list):
            out["buckets"] = [{"name": str(x.get("name") or x.get("id"))[:100], "public": bool(x.get("public"))} for x in b.json()[:50]]
        else: out["buckets"] = []
    except Exception: out["buckets"] = None
    return out

# ---------- 报告 ----------
ADVICE_RLS = [
    "对 public schema 中的每张表开启行级安全（RLS）：开启后没有策略的表对 anon 默认不可读。",
    "只为确实需要公开的数据写 SELECT 策略；用户私有数据按 auth.uid() 限制。",
    "不需要被前端直接访问的表，撤销 anon 角色权限：revoke all on table public.<表名> from anon;",
    "在 Supabase 控制台 Advisors → Security Advisor 复查，确认没有 “RLS disabled in public” 告警。",
]
SQL_EXAMPLE = """-- 1) 开启 RLS（开启后无策略 = 拒绝所有 anon/authenticated 访问）
alter table public.profiles enable row level security;

-- 2) 只允许登录用户读写自己的行
create policy "own rows - select" on public.profiles
  for select to authenticated using (auth.uid() = user_id);
create policy "own rows - update" on public.profiles
  for update to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id);

-- 3) 不需要前端直连的表，直接撤销 anon 权限
revoke all on table public.internal_logs from anon;

-- 4) 检查哪些表还没开启 RLS
select schemaname, tablename from pg_tables
 where schemaname = 'public' and rowsecurity = false;"""
ADVICE_SECRET = [
    "立即在 Supabase 控制台 Project Settings → API Keys 轮换 service_role / secret key（旧 key 失效前任何人都能绕过 RLS 读写全库）。",
    "service_role / sb_secret_ key 只能放在服务端（Edge Function、后端环境变量），绝不能出现在前端代码或 VITE_/NEXT_PUBLIC_ 变量里。",
    "轮换后检查数据库与 Storage 是否有被篡改或导出的迹象（Logs → API / Postgres）。",
]

def build_report(passive, deep=None):
    findings = []
    for k in passive["keys"]:
        if k["role"] == "service_role":
            findings.append({"severity": "critical", "title": "前端代码中暴露了 service_role / secret key",
                             "detail": f"{k['preview']}（位置：{k['where']}）— 该 key 可绕过 RLS 完全读写数据库"})
    anon = [k for k in passive["keys"] if k["role"] == "anon"]
    if anon:
        findings.append({"severity": "info", "title": f"公开 JS 中发现 Supabase anon / publishable key（{len(anon)} 个）",
                         "detail": "这是正常现象（anon key 本就公开），安全完全依赖 RLS。" + "；".join(f"{k['preview']}（{k['where']}）" for k in anon[:5])})
    if deep:
        rd = [t for t in deep["tables"] if t["rows_visible"]]
        for t in rd:
            sev = "critical" if t["pii_columns"] else "high"
            cnt = f"约 {t['count']} 行" if t["count"] is not None else "行数未知"
            findings.append({"severity": sev, "title": f"表 {t['name']} 可被匿名读取（{cnt}）",
                             "detail": ("疑似敏感列：" + "、".join(t["pii_columns"][:12])) if t["pii_columns"] else "列：" + "、".join(t["columns"][:12])})
        empty = [t["name"] for t in deep["tables"] if t["readable"] and not t["rows_visible"]]
        if empty:
            findings.append({"severity": "low", "title": f"{len(empty)} 张表对 anon 可访问但未返回数据",
                             "detail": "可能是空表，或 RLS 已开启且过滤了全部行：" + "、".join(empty[:15])})
        if deep["openapi"] == "exposed" and deep.get("table_total"):
            findings.append({"severity": "low", "title": f"anon key 可读取 API 表结构（{deep['table_total']} 张表/视图，{deep['rpc_count']} 个 RPC 函数）",
                             "detail": "攻击者可借此枚举表名与列名。可在 Supabase 中关闭 anon 对 OpenAPI 的访问，或撤销不必要的表权限。"})
        pub = [b["name"] for b in (deep["buckets"] or []) if b["public"]]
        if pub:
            findings.append({"severity": "medium", "title": f"{len(pub)} 个 Storage bucket 为公开（public）",
                             "detail": "知道文件路径即可下载，确认里面没有用户上传的私密文件：" + "、".join(pub[:10])})
        if deep["buckets"]:
            findings.append({"severity": "low", "title": "anon key 可列出 Storage bucket 列表", "detail": "、".join(b["name"] for b in deep["buckets"][:10])})
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: order[f["severity"]])
    summary = {s: sum(1 for f in findings if f["severity"] == s) for s in order}
    advice = []
    if any(f["severity"] == "critical" and "service_role" in f["title"] for f in findings): advice += ADVICE_SECRET
    if deep and any(t["rows_visible"] for t in deep["tables"]) or (deep and deep.get("table_total")): advice += ADVICE_RLS
    elif anon and not deep: advice += ["请先完成站点所有权验证，再做深度检测，确认每张表都开启了 RLS。"] + ADVICE_RLS[:1]
    return {"summary": summary, "findings": findings, "advice": advice,
            "sql_example": SQL_EXAMPLE if (deep and any(t["readable"] for t in deep["tables"])) or anon else None}

def report_text(r):
    L = [f"Supabase 数据暴露扫描报告：{r['host']}", f"扫描时间：{r['scanned_at']}（UTC）", f"模式：{'深度（已验证所有权）' if r.get('deep') else '被动（仅公开 JS）'}", ""]
    s = r["report"]["summary"]
    L.append("严重 {critical}｜高 {high}｜中 {medium}｜低 {low}｜提示 {info}".format(**s)); L.append("")
    for f in r["report"]["findings"]: L += [f"[{f['severity'].upper()}] {f['title']}", f"    {f['detail']}"]
    if not r["report"]["findings"]: L.append("未发现 Supabase 相关配置。")
    if r["report"]["advice"]: L += ["", "修复建议："] + [f"{i+1}. {a}" for i, a in enumerate(r["report"]["advice"])]
    if r["report"].get("sql_example"): L += ["", "示例 SQL：", r["report"]["sql_example"]]
    L += ["", "— cert-checker · https://cert-checker-h6lr.onrender.com/supabase-check"]
    return "\n".join(L)

# ---------- 结果暂存（供发邮件，1 小时） ----------
_store, _lock = {}, threading.Lock()
def stash(res):
    rid = secrets.token_urlsafe(12)
    with _lock:
        now = time.time()
        for k in [k for k, (t, _) in _store.items() if now - t > 3600]: _store.pop(k, None)
        _store[rid] = (now, res)
    return rid
def fetch_stash(rid):
    with _lock:
        v = _store.get(rid)
    return v[1] if v and time.time() - v[0] < 3600 else None

def scan(raw_site: str, deep=False):
    import datetime as dt
    host = parse_site(raw_site)
    p = passive_scan(host)
    raw_keys = p.pop("_raw_keys")
    res = {"host": host, "final_host": p["final_host"], "deep": False, "passive": p,
           "scanned_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")}
    deep_res = None
    if deep:
        v = {"ok": False}
        if not same_site(p["final_host"], host):
            v["error"] = f"该网站跳转到了 {p['final_host']}，请直接输入并验证最终域名"
        else:
            ok, method, tried = check_ownership(host)
            v = {"ok": ok, "method": method, "tried": tried}
            if not ok: v["error"] = "未通过所有权验证，只做了被动扫描"
        res["verification"] = v
        if v["ok"]:
            anon = [(k, i) for k, i in raw_keys if i["role"] == "anon"]
            projects = p["projects"] or sorted({i["ref"] for _, i in anon if i["ref"]})
            if not projects or not anon:
                res["deep_note"] = "页面中没有同时找到 Supabase 项目地址和 anon key，无法做深度检测"
            else:
                ref = projects[0]
                key = next((k for k, i in anon if i["ref"] == ref), anon[0][0])
                deep_res = deep_scan(ref, key)
                res["deep"] = True; res["deep_result"] = deep_res
        del raw_keys
    res["report"] = build_report(p, deep_res)
    res["found_supabase"] = bool(p["projects"] or p["keys"])
    res["report_id"] = stash(res)
    return res
