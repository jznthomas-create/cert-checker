"""每周健康周报：每个订阅邮箱一封，汇总其全部已确认域名的证书 / 域名到期 / 站点状态。"""
import datetime as dt, html, os, sys
sys.path.insert(0, os.path.dirname(__file__))
import db, mailer, health
from app import inspect, CheckError

MIN_INTERVAL_H = float(os.getenv("DIGEST_MIN_INTERVAL_H", "144"))  # 6 天内不重复发
ICON = {"bad": "🔴", "warn": "🟠", "info": "ℹ️"}

def check_domain(d):
    try: cert = inspect(d)
    except CheckError as e: cert = {"error": e.msg}
    dom = health.domain_expiry(d)
    site = health.site_health(d)
    return {"domain": d, "cert": cert, "dom": dom, "site": site, "issues": health.issues(cert, dom, site)}

def _cert_days(r): return "—" if r["cert"].get("error") else f"{r['cert']['leaf']['days_left']} 天"
def _dom_days(r): return f"{r['dom']['days_left']} 天" if r["dom"].get("days_left") is not None else "未知"
def _http(r):
    s = r["site"]
    if s.get("error"): return "失败"
    return f"{s['status']}（{s['response_ms']} ms）"
def _issuer(r): return "—" if r["cert"].get("error") else (r["cert"]["leaf"].get("issuer_org") or r["cert"]["leaf"].get("issuer_cn") or "—")

def render(email, rows, subs, base_url):
    """rows: check_domain 结果；subs: 该邮箱的订阅行。返回 (subject, text, html)。"""
    n_bad = sum(1 for r in rows if any(l == "bad" for l, _ in r["issues"]))
    n_warn = sum(1 for r in rows if not any(l == "bad" for l, _ in r["issues"]) and any(l == "warn" for l, _ in r["issues"]))
    status = f"{n_bad} 个需处理" if n_bad else (f"{n_warn} 个需留意" if n_warn else "全部正常")
    subject = f"[网站健康周报] {len(rows)} 个域名，{status}"
    unsub = {s["domain"]: f"{base_url}/api/unsubscribe?token={s['unsub_token']}" for s in subs}
    unsub_all = f"{base_url}/api/unsubscribe-all?token={subs[0]['unsub_token']}"
    today = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).strftime("%Y-%m-%d")
    # 纯文本
    t = [f"网站健康周报（{today}）", "Weekly domain, certificate & site health digest.", ""]
    for r in rows:
        t.append(f"■ {r['domain']}  证书剩余 {_cert_days(r)} | 域名剩余 {_dom_days(r)} | HTTP {_http(r)} | CA {_issuer(r)}")
        t += [f"   {ICON[l]} {m}" for l, m in r["issues"]] or ["   ✅ 一切正常"]
    t += ["", "退订某个域名："] + [f"  {d}: {u}" for d, u in unsub.items()] + [f"全部退订：{unsub_all}", "", f"查看详情：{base_url}"]
    text = "\n".join(t)
    # HTML
    e = html.escape
    color = {"bad": "#dc2626", "warn": "#d97706", "info": "#64748b"}
    def cell(v, lvl=None): return f'<td style="padding:6px 8px;border-bottom:1px solid #e5e7eb;{f"color:{color[lvl]};font-weight:600" if lvl else ""}">{e(v)}</td>'
    def lvl_days(days, bad, warn):
        if days is None: return None
        return "bad" if days <= bad else ("warn" if days <= warn else None)
    trs = []
    for r in rows:
        cd = None if r["cert"].get("error") else r["cert"]["leaf"]["days_left"]
        dd = r["dom"].get("days_left"); s = r["site"]
        hl = "bad" if s.get("error") or (s.get("status") or 0) >= 400 else None
        iss = "<br>".join(f'<span style="color:{color[l]}">{ICON[l]} {e(m)}</span>' for l, m in r["issues"]) or '<span style="color:#16a34a">✅ 正常</span>'
        trs.append("<tr>" + cell(r["domain"]) + cell(_cert_days(r), "bad" if r["cert"].get("error") else lvl_days(cd, 14, 30))
                   + cell(_dom_days(r), lvl_days(dd, 30, 60)) + cell(_http(r), hl)
                   + f'<td style="padding:6px 8px;border-bottom:1px solid #e5e7eb;font-size:12px">{iss}<br>'
                   + f'<a href="{e(unsub[r["domain"]])}" style="color:#94a3b8;font-size:11px">退订此域名</a></td></tr>')
    th = "".join(f'<th style="text-align:left;padding:6px 8px;background:#f1f5f9">{h}</th>' for h in ["域名", "证书剩余", "域名剩余", "HTTP", "问题"])
    body = f"""<div style="font-family:-apple-system,'PingFang SC','Microsoft YaHei',sans-serif;color:#1f2937;max-width:720px">
<h2 style="margin:0 0 4px">网站健康周报 · {today}</h2>
<p style="margin:0 0 12px;color:#64748b;font-size:13px">Weekly domain, certificate &amp; site health digest. 本周：<b>{e(status)}</b></p>
<table style="border-collapse:collapse;width:100%;font-size:14px"><tr>{th}</tr>{''.join(trs)}</table>
<p style="font-size:12px;color:#94a3b8;margin-top:16px">证书 ≤14 天或域名 ≤30 天标红。数据来自 TLS 握手、RDAP 与首页 HTTPS 请求。
<a href="{e(base_url)}">在线查看</a> · <a href="{e(unsub_all)}">全部退订</a></p></div>"""
    return subject, text, body

def _recent(ts):
    if not ts: return False
    try: t = dt.datetime.fromisoformat(ts)
    except ValueError: return False
    return (dt.datetime.now(dt.timezone.utc) - t).total_seconds() < MIN_INTERVAL_H * 3600

def run(force=False, only_email=None):
    base_url = os.getenv("BASE_URL", "http://127.0.0.1:8000")
    subs = db.verified(); by_email = {}
    for s in subs:
        if only_email and s["email"] != only_email: continue
        by_email.setdefault(s["email"], []).append(s)
    cache, results = {}, []
    for email, ss in by_email.items():
        if not force and all(_recent(s.get("last_digest_at")) for s in ss):
            results.append({"to": email, "skipped": "本周已发送"}); continue
        rows = []
        for s in ss:
            if s["domain"] not in cache: cache[s["domain"]] = check_domain(s["domain"])
            rows.append(cache[s["domain"]])
        subject, text, body = render(email, rows, ss, base_url)
        res = mailer.send(email, subject, text, html=body)
        item = {"to": email, "domains": len(rows), "ok": bool(res), "id": res if isinstance(res, str) else None}
        if not res: item["error"] = mailer.last_error
        else:
            for s in ss: db.update(s["id"], last_digest_at=db.now())
        results.append(item)
    sent = sum(1 for r in results if r.get("ok"))
    mailer.log.info("周报完成：邮箱 %d 个，域名 %d 个，发送 %d 封", len(by_email), len(cache), sent)
    return {"emails": len(by_email), "domains": len(cache), "sent": sent, "results": results}

if __name__ == "__main__": print(run(force="--force" in sys.argv))
