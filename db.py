import os, sqlite3, secrets, datetime as dt
DB_PATH = os.getenv("DB_PATH", os.path.join(os.path.dirname(__file__), "data", "subs.db"))
THRESHOLDS = [30, 14, 7, 1]

def conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    c = sqlite3.connect(DB_PATH); c.row_factory = sqlite3.Row
    c.execute("""CREATE TABLE IF NOT EXISTS subscriptions(
        id INTEGER PRIMARY KEY, email TEXT NOT NULL, domain TEXT NOT NULL,
        verified INTEGER DEFAULT 0, confirm_token TEXT, unsub_token TEXT NOT NULL,
        created_at TEXT, last_serial TEXT, last_not_after TEXT, notified_thresholds TEXT DEFAULT '',
        last_checked_at TEXT, last_error TEXT, UNIQUE(email, domain))""")
    return c

def now(): return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")

def add(email, domain):
    """新建或返回已有订阅；返回 (row, created)。"""
    with conn() as c:
        r = c.execute("SELECT * FROM subscriptions WHERE email=? AND domain=?", (email, domain)).fetchone()
        if r: return r, False
        if c.execute("SELECT COUNT(*) FROM subscriptions WHERE email=?", (email,)).fetchone()[0] >= int(os.getenv("MAX_SUBS_PER_EMAIL", "20")):
            raise ValueError("该邮箱订阅数量已达上限")
        c.execute("INSERT INTO subscriptions(email,domain,confirm_token,unsub_token,created_at) VALUES(?,?,?,?,?)",
                  (email, domain, secrets.token_urlsafe(24), secrets.token_urlsafe(24), now()))
        return c.execute("SELECT * FROM subscriptions WHERE email=? AND domain=?", (email, domain)).fetchone(), True

def confirm(token):
    with conn() as c:
        r = c.execute("SELECT * FROM subscriptions WHERE confirm_token=?", (token,)).fetchone()
        if r: c.execute("UPDATE subscriptions SET verified=1, confirm_token=NULL WHERE id=?", (r["id"],))
        return r

def unsubscribe(token):
    with conn() as c:
        r = c.execute("SELECT * FROM subscriptions WHERE unsub_token=?", (token,)).fetchone()
        if r: c.execute("DELETE FROM subscriptions WHERE id=?", (r["id"],))
        return r

def verified():
    with conn() as c: return c.execute("SELECT * FROM subscriptions WHERE verified=1").fetchall()

def update(id_, **kw):
    with conn() as c:
        c.execute(f"UPDATE subscriptions SET {', '.join(k+'=?' for k in kw)} WHERE id=?", (*kw.values(), id_))
