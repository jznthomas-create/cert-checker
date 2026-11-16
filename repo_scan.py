"""公开 GitHub 仓库密钥泄露扫描（只读、只扫高风险路径，不下载整个仓库）。

安全约定：任何地方都不保存、不返回、不记录完整密钥，只保留类型、文件、行号和脱敏预览。
网络只访问固定的 api.github.com 与 raw.githubusercontent.com，不跟随跳转。
"""
import datetime as dt, fnmatch, json, logging, math, os, re
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote
import httpx
import db

log = logging.getLogger("repo_scan")
API = "https://api.github.com"
RAW = "https://raw.githubusercontent.com"
UA = "cert-checker-repo-scan/1.0 (+https://cert-checker-h6lr.onrender.com)"
CACHE_TTL = float(os.getenv("REPO_SCAN_CACHE_H", "6")) * 3600
QUICK_TTL = 30 * 60  # 快速模式结果只缓存 30 分钟，额度恢复后尽快做完整扫描
MAX_FILES = int(os.getenv("REPO_SCAN_MAX_FILES", "40"))
MAX_BYTES = 256 * 1024

class ScanError(Exception):
    def __init__(self, msg, code=400): super().__init__(msg); self.msg, self.code = msg, code

# ---------- 输入解析 ----------
NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
REPO_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")

def parse_repo(raw: str) -> str:
    """接受 owner/repo、github.com/owner/repo、https://github.com/owner/repo(.git)(/tree/...)。返回小写 owner/repo。"""
    s = (raw or "").strip()
    s = re.sub(r"^git@github\.com:", "", s, flags=re.I)
    s = re.sub(r"^https?://", "", s, flags=re.I)
    s = re.sub(r"^(www\.)?github\.com/", "", s, flags=re.I)
    if "://" in s or s.lower().startswith(("http", "//")): raise ScanError("只支持 github.com 上的公开仓库")
    if re.match(r"^[^/]+\.[a-z]{2,}/", s, re.I) and not s.lower().startswith("github.com"):
        if "." in s.split("/")[0]: raise ScanError("只支持 github.com 上的公开仓库")
    parts = [p for p in s.split("?")[0].split("#")[0].split("/") if p]
    if len(parts) < 2: raise ScanError("请输入 owner/repo 或 GitHub 仓库链接")
    owner, repo = parts[0], re.sub(r"\.git$", "", parts[1])
    if not NAME_RE.match(owner) or not REPO_RE.match(repo) or repo in (".", ".."):
        raise ScanError("仓库名格式无效")
    return f"{owner}/{repo}".lower()

# ---------- 候选文件 ----------
EXAMPLE_HINTS = ("example", "sample", "template", "dist", "defaults", "default", "tmpl", "schema")
NAME_GLOBS = [".env", ".env.*", "*.env", ".envrc", "credentials.json", "credentials", "client_secret*.json",
              "service-account*.json", "serviceaccount*.json", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
              "*.pem", "*.key", "*.p12", "*.pfx", ".npmrc", ".pypirc", ".netrc", "_netrc", ".git-credentials",
              ".pgpass", "secrets.yml", "secrets.yaml", "secrets.json", ".mcp.json", "mcp.json", "mcp_config.json",
              "wp-config.php", ".s3cfg", ".htpasswd", "terraform.tfvars", "*.tfvars", ".dockercfg"]
PATH_GLOBS = [".claude/*", "*/.claude/*", ".cursor/*", "*/.cursor/*", ".vscode/mcp.json", ".aws/credentials",
              "*/.aws/credentials", ".docker/config.json", ".codeium/*", ".windsurf/*", ".continue/*"]
AGENT_HINT = (".claude/", ".cursor/", ".mcp.json", "mcp.json", "mcp_config.json", ".codeium/", ".windsurf/", ".continue/")
BINARY_EXT = (".p12", ".pfx")

def is_candidate(path: str) -> bool:
    p = path.lower(); base = p.rsplit("/", 1)[-1]
    if "node_modules/" in p or "/vendor/" in p or p.startswith("vendor/"): return False
    if any(fnmatch.fnmatch(base, g) for g in NAME_GLOBS): return True
    return any(fnmatch.fnmatch(p, g) for g in PATH_GLOBS)

def is_example(path: str) -> bool:
    p = path.lower()
    return any(h in p.rsplit("/", 1)[-1] for h in EXAMPLE_HINTS) or "/test" in "/" + p or "/fixtures/" in p or "/docs/" in "/" + p

def priority(path):
    p = path.lower()
    if any(h in p for h in AGENT_HINT): return 0
    if not is_example(path): return 1
    return 2

# ---------- 检测规则 ----------
RULES = [  # (类型, 正则)。顺序重要：更具体的在前。
    ("私钥 Private key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----")),
    ("Anthropic API Key", re.compile(r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{30,}")),
    ("OpenAI API Key", re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}|\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}|\bsk-[A-Za-z0-9]{48}\b")),
    ("GitHub Token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}")),
    ("AWS Access Key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Stripe Live Key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}")),
    ("Hugging Face Token", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    ("Resend API Key", re.compile(r"\bre_[A-Za-z0-9]{8}_[A-Za-z0-9]{20,}")),
    ("npm Token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("Groq API Key", re.compile(r"\bgsk_[A-Za-z0-9]{40,}")),
    ("xAI API Key", re.compile(r"\bxai-[A-Za-z0-9]{60,}")),
    ("数据库连接串含密码", re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s/@'\"]{1,64}:([^@\s'\"]{6,})@[^\s'\"]+")),
]
ASSIGN_RE = re.compile(r"""^\s*(?:export\s+)?["']?([A-Za-z_][A-Za-z0-9_.-]*)["']?\s*[:=]\s*["']?([^"'\s#,]{8,})""")
SENSITIVE_KEY = re.compile(r"(?i)(secret|token|passw|pwd|api[_-]?key|apikey|access[_-]?key|private[_-]?key|auth|credential|client[_-]?secret)")
PLACEHOLDER = re.compile(r"(?i)^(your|my|<|\$\{|\$\(|\{\{|%|xxx|\*\*\*|changeme|change_me|replace|example|sample|dummy|placeholder|todo|null|none|true|false|test|password|secret|redacted|insert|enter|put)|xxxx|\.\.\.|your[_-]|_here$|-here$")

def entropy(s):
    c = Counter(s); n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())

def redact(v: str) -> str:
    v = v.strip()
    if v.startswith("-----BEGIN"): return "-----BEGIN … PRIVATE KEY----- (已隐藏)"
    if len(v) >= 16: return f"{v[:4]}…{v[-2:]}（共 {len(v)} 位）"
    return f"{v[:2]}****（共 {len(v)} 位）"

def scan_text(path: str, text: str):
    """返回 findings 列表：{type, path, line, preview, example}。不包含原文。"""
    out, seen = [], set()
    envlike = True  # 候选文件本身都是高风险配置，允许“敏感键名=高熵值”规则
    for i, line in enumerate(text.splitlines()[:5000], 1):
        if len(line) > 4000: line = line[:4000]
        hit = False
        for typ, rx in RULES:
            for m in rx.finditer(line):
                val = m.group(1) if m.groups() and m.group(1) else m.group(0)
                key = (typ, i)
                if key in seen: continue
                seen.add(key); hit = True
                out.append({"type": typ, "path": path, "line": i, "preview": redact(val)})
        if hit or not envlike: continue
        m = ASSIGN_RE.match(line)
        if m and SENSITIVE_KEY.search(m.group(1)):
            val = m.group(2)
            if PLACEHOLDER.search(val) or len(set(val)) < 6 or entropy(val) < 3.3: continue
            if re.fullmatch(r"[a-z_.-]+", val) or re.fullmatch(r"\d+", val): continue
            out.append({"type": f"疑似密钥（{m.group(1)[:40]}）", "path": path, "line": i, "preview": redact(val)})
    ex = is_example(path)
    for f in out: f["example"] = ex
    return out

# ---------- GitHub 访问 ----------
def _headers():
    h = {"user-agent": UA, "accept": "application/vnd.github+json", "x-github-api-version": "2022-11-28"}
    tok = os.getenv("GITHUB_TOKEN")  # 可选：只读 token 提高额度；不设置也能用
    if tok: h["authorization"] = f"Bearer {tok}"
    return h

def _api(path):
    try: r = httpx.get(API + path, headers=_headers(), timeout=12, follow_redirects=False)
    except httpx.TimeoutException: raise ScanError("连接 GitHub 超时，请稍后再试", 504)
    except httpx.HTTPError as e: raise ScanError(f"连接 GitHub 失败：{type(e).__name__}", 502)
    if r.status_code in (403, 429) and (r.headers.get("x-ratelimit-remaining") == "0" or r.status_code == 429 or "rate limit" in r.text.lower()):
        reset = r.headers.get("x-ratelimit-reset"); wait = ""
        try: wait = f"，约 {min(60, max(1, int((int(reset) - dt.datetime.now().timestamp()) // 60) + 1))} 分钟后恢复" if reset else ""
        except ValueError: pass
        raise ScanError(f"GitHub 接口额度暂时用完{wait}，请稍后再试", 429)
    if r.status_code in (404, 451) or (r.status_code == 403 and "blocked" in r.text.lower()):
        raise ScanError("仓库不存在或不是公开仓库（只支持公开仓库）", 404)
    if r.status_code in (301, 302, 307): raise ScanError("该仓库已改名或迁移，请输入新的仓库地址", 400)
    if r.status_code == 409: raise ScanError("仓库是空的", 400)
    if r.status_code >= 400: raise ScanError(f"GitHub 返回错误 {r.status_code}", 502)
    return r.json()

def _raw(full, ref, path):
    url = f"{RAW}/{full}/{quote(ref, safe='')}/{quote(path)}"
    try:
        r = httpx.get(url, headers={"user-agent": UA}, timeout=10, follow_redirects=False)
        if r.status_code != 200: return None
        return r.content[:MAX_BYTES].decode("utf-8", "replace")
    except httpx.HTTPError: return None

QUICK_PATHS = [".env", ".env.local", ".env.production", ".env.prod", ".env.development", ".env.dev", ".env.staging", ".env.test",
               ".claude/settings.local.json", ".claude/settings.json", ".cursor/mcp.json", ".mcp.json", "mcp.json", ".vscode/mcp.json",
               ".windsurf/mcp.json", ".codeium/windsurf/mcp_config.json", ".continue/config.json", ".continue/config.yaml",
               "credentials.json", "client_secret.json", "service-account.json", "id_rsa", "id_ed25519", "key.pem", "private.pem",
               "server.key", ".npmrc", ".pypirc", ".netrc", ".git-credentials", ".docker/config.json", ".aws/credentials", ".envrc",
               "config/secrets.yml", "config/master.key", "secrets.json", "secrets.yaml", "backend/.env", "server/.env", "api/.env",
               "frontend/.env", "app/.env", "web/.env", "src/.env", "docker/.env", "terraform.tfvars"]

def _repo_public(full):
    try:
        r = httpx.get(f"https://github.com/{full}", headers={"user-agent": UA}, timeout=10, follow_redirects=False)
        if r.status_code in (200, 301, 302): return True
        return False if r.status_code == 404 else None
    except httpx.HTTPError: return None

def now(): return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")

def scan(raw_repo: str, use_cache=True):
    full = parse_repo(raw_repo)
    if use_cache:
        c = db.repo_cache_get(full)
        if c:
            try:
                age = (dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(c["scanned_at"])).total_seconds()
                res = json.loads(c["result"])
                if age < (QUICK_TTL if res.get("mode") == "quick" else CACHE_TTL):
                    res["cached"] = True; return res
            except (ValueError, TypeError): pass
    if os.getenv("GITHUB_TOKEN"):  # 带 token 时显式确认仓库是公开的，避免扫到 token 能看到的私有仓库
        meta = _api(f"/repos/{full}")
        if meta.get("private"): raise ScanError("只支持公开仓库", 403)
    # 未登录访问只能看到公开仓库；用 HEAD 指向默认分支，每次扫描只消耗 1 次 GitHub API 额度
    branch, mode = "HEAD", "full"
    try:
        tree = _api(f"/repos/{full}/git/trees/HEAD?recursive=1")
        blobs = [t for t in tree.get("tree", []) if t.get("type") == "blob"]
        cands = sorted((t for t in blobs if is_candidate(t["path"])), key=lambda t: (priority(t["path"]), t["path"]))
    except ScanError as e:
        if e.code != 429: raise
        # 共享出口 IP 的 GitHub API 额度常被别人用完：退回“快速模式”，直接探测常见路径（不消耗 API 额度）
        pub = _repo_public(full)
        if pub is False: raise ScanError("仓库不存在或不是公开仓库（只支持公开仓库）", 404)
        if pub is None: raise e   # github.com 也被限流：如实报告额度问题
        mode, tree, blobs = "quick", {}, []
        cands = [{"path": p, "size": 0} for p in QUICK_PATHS]
    skipped = max(0, len(cands) - MAX_FILES); cands = cands[:MAX_FILES]
    def one(t):
        if t.get("size", 0) > MAX_BYTES or t["path"].lower().endswith(BINARY_EXT):
            return t["path"], None, "文件过大或为二进制，未扫描内容"
        txt = _raw(full, branch, t["path"])
        return t["path"], txt, None if txt is not None else "下载失败"
    files, findings = [], []
    with ThreadPoolExecutor(max_workers=8) as ex:
        for path, txt, note in ex.map(one, cands):
            if mode == "quick" and txt is None: continue   # 快速模式下不存在的路径直接忽略
            fs = scan_text(path, txt) if txt is not None else []
            files.append({"path": path, "findings": len(fs), "note": note, "example": is_example(path)})
            findings += fs
    real = [f for f in findings if not f["example"]]
    res = {"repo": full, "url": f"https://github.com/{full}", "branch": branch, "scanned_at": now(),
           "files_scanned": len(files), "files": files, "files_skipped": skipped,
           "tree_truncated": bool(tree.get("truncated")), "total_files": len(blobs),
           "findings": findings[:200], "count": len(findings), "count_real": len(real),
           "level": "bad" if real else ("warn" if findings else "ok"), "cached": False, "mode": mode,
           "quick_paths": len(QUICK_PATHS) if mode == "quick" else 0}
    db.repo_cache_put(full, json.dumps(res, ensure_ascii=False), res["scanned_at"])
    log.info("repo scan %s files=%d findings=%d", full, len(files), len(findings))  # 不记录任何内容
    return res

ADVICE = [
    "立即到对应平台吊销/轮换泄露的密钥（删除提交不够，Git 历史和 fork 里仍然能看到）。",
    "把 .env、.claude/settings.local.json、.cursor/mcp.json 等加入 .gitignore，只提交 .env.example。",
    "用 git filter-repo 或 BFG 清理历史后强制推送，并检查平台账单/访问日志有无异常调用。",
    "开启 GitHub Secret Scanning / Push Protection，防止 AI 编程工具再次把密钥提交上去。",
]
