"""订阅存储：有 DATABASE_URL 时用 Postgres（psycopg 3），否则回退 SQLite。"""
import os, sqlite3, secrets, datetime as dt
from contextlib import contextmanager

THRESHOLDS = [30, 14, 7, 1]
COLS = """email TEXT NOT NULL, domain TEXT NOT NULL,
    verified INTEGER DEFAULT 0, confirm_token TEXT, unsub_token TEXT NOT NULL,
    created_at TEXT, last_serial TEXT, last_not_after TEXT, notified_thresholds TEXT DEFAULT '',
    last_checked_at TEXT, last_error TEXT, UNIQUE(email, domain)"""
_ready = set()

def _url(): return os.getenv("DATABASE_URL")
def _sqlite_path(): return os.getenv("DB_PATH", os.path.join(os.path.dirname(__file__), "data", "subs.db"))
def backend(): return "postgres" if _url() else "sqlite"

@contextmanager
def conn():
    """yield (cursor, 占位符)；退出时提交。"""
    if _url():
        import psycopg
        from psycopg.rows import dict_row
        with psycopg.connect(_url(), row_factory=dict_row, connect_timeout=10) as c:
            cur = c.cursor()
            if _url() not in _ready:
                cur.execute(f"CREATE TABLE IF NOT EXISTS subscriptions(id SERIAL PRIMARY KEY, {COLS})"); _ready.add(_url())
            yield cur, "%s"
    else:
        p = _sqlite_path(); os.makedirs(os.path.dirname(p), exist_ok=True)
        c = sqlite3.connect(p); c.row_factory = lambda cur, row: {d[0]: row[i] for i, d in enumerate(cur.description)}
        try:
            cur = c.cursor()
            cur.execute(f"CREATE TABLE IF NOT EXISTS subscriptions(id INTEGER PRIMARY KEY, {COLS})")
            yield cur, "?"; c.commit()
        finally: c.close()

def _q(sql, ph): return sql.replace("?", ph)
def now(): return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")

def _one(cur, ph, sql, args): cur.execute(_q(sql, ph), args); return cur.fetchone()

def add(email, domain):
    with conn() as (cur, ph):
        r = _one(cur, ph, "SELECT * FROM subscriptions WHERE email=? AND domain=?", (email, domain))
        if r: return r, False
        n = _one(cur, ph, "SELECT COUNT(*) AS n FROM subscriptions WHERE email=?", (email,))["n"]
        if n >= int(os.getenv("MAX_SUBS_PER_EMAIL", "20")): raise ValueError("该邮箱订阅数量已达上限")
        cur.execute(_q("INSERT INTO subscriptions(email,domain,confirm_token,unsub_token,created_at) VALUES(?,?,?,?,?)", ph),
                    (email, domain, secrets.token_urlsafe(24), secrets.token_urlsafe(24), now()))
        return _one(cur, ph, "SELECT * FROM subscriptions WHERE email=? AND domain=?", (email, domain)), True

def confirm(token):
    with conn() as (cur, ph):
        r = _one(cur, ph, "SELECT * FROM subscriptions WHERE confirm_token=?", (token,))
        if r: cur.execute(_q("UPDATE subscriptions SET verified=1, confirm_token=NULL WHERE id=?", ph), (r["id"],))
        return r

def unsubscribe(token):
    with conn() as (cur, ph):
        r = _one(cur, ph, "SELECT * FROM subscriptions WHERE unsub_token=?", (token,))
        if r: cur.execute(_q("DELETE FROM subscriptions WHERE id=?", ph), (r["id"],))
        return r

def verified():
    with conn() as (cur, ph): cur.execute("SELECT * FROM subscriptions WHERE verified=1 ORDER BY id"); return cur.fetchall()

def update(id_, **kw):
    with conn() as (cur, ph):
        cur.execute(_q(f"UPDATE subscriptions SET {', '.join(k+'=?' for k in kw)} WHERE id=?", ph), (*kw.values(), id_))

def stats():
    with conn() as (cur, ph):
        cur.execute("SELECT COUNT(*) AS total, COALESCE(SUM(verified),0) AS verified FROM subscriptions"); r = cur.fetchone()
        return {"backend": backend(), "total": int(r["total"]), "verified": int(r["verified"])}
