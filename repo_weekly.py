"""仓库密钥泄露周报：每个邮箱一封，重新扫描其订阅的全部公开仓库。邮件中只有脱敏预览。"""
import datetime as dt, html, os
import db, mailer, repo_scan

MIN_INTERVAL_H = float(os.getenv("DIGEST_MIN_INTERVAL_H", "144"))

def _recent(ts):
    if not ts: return False
    try: return (dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(ts)).total_seconds() < MIN_INTERVAL_H * 3600
    except ValueError: return False

def scan_safe(repo):
    try: return repo_scan.scan(repo, use_cache=False)
    except repo_scan.ScanError as e: return {"repo": repo, "error": e.msg, "findings": [], "count_real": 0, "count": 0}

def render(rows, subs, base_url):
    bad = sum(1 for r in rows if r.get("count_real"))
    subject = f"[仓库密钥周报] {len(rows)} 个仓库，" + (f"{bad} 个发现疑似泄露" if bad else "未发现泄露")
    unsub = {s["repo"]: f"{base_url}/api/repo/unsubscribe?token={s['unsub_token']}" for s in subs}
    today = dt.datetime.now(dt.timezone(dt.timedelta(hours=8))).strftime("%Y-%m-%d")
    e = html.escape
    t, h = [f"仓库密钥泄露周报（{today}）", "Weekly public-repo secret leak scan.", ""], []
    for r in rows:
        if r.get("error"):
            t.append(f"■ {r['repo']}：扫描失败（{r['error']}）"); h.append(f"<h3>{e(r['repo'])}</h3><p style='color:#d97706'>扫描失败：{e(r['error'])}</p>")
        else:
            t.append(f"■ {r['repo']}：扫描 {r['files_scanned']} 个高风险文件，疑似泄露 {r['count_real']} 处（示例/测试文件 {r['count'] - r['count_real']} 处）")
            items = [f for f in r["findings"] if not f["example"]][:20]
            t += [f"   🔴 {f['path']}:{f['line']}  {f['type']}  {f['preview']}" for f in items] or ["   ✅ 未发现"]
            li = "".join(f"<li><code>{e(f['path'])}:{f['line']}</code> {e(f['type'])} <code>{e(f['preview'])}</code></li>" for f in items)
            h.append(f"<h3 style='margin:16px 0 4px'><a href='{e(r['url'])}'>{e(r['repo'])}</a></h3>"
                     + (f"<ul style='color:#dc2626'>{li}</ul>" if li else "<p style='color:#16a34a'>✅ 未发现疑似泄露</p>"))
        h.append(f"<a href='{e(unsub[r['repo']])}' style='color:#94a3b8;font-size:11px'>退订此仓库</a>")
        t.append(f"   退订：{unsub[r['repo']]}")
    if bad: t += ["", "处理建议："] + [f"  {i}. {a}" for i, a in enumerate(repo_scan.ADVICE, 1)]
    t += ["", f"在线扫描：{base_url}/repo-check"]
    adv = "<ol style='font-size:13px'>" + "".join(f"<li>{e(a)}</li>" for a in repo_scan.ADVICE) + "</ol>" if bad else ""
    body = (f"<div style=\"font-family:-apple-system,'PingFang SC','Microsoft YaHei',sans-serif;color:#1f2937;max-width:720px\">"
            f"<h2>仓库密钥泄露周报 · {today}</h2><p style='color:#64748b;font-size:13px'>只扫描公开仓库默认分支中的 .env、.claude、.cursor、私钥等高风险文件；密钥只显示脱敏预览。</p>"
            + "".join(h) + adv + f"<p style='font-size:12px;color:#94a3b8'><a href='{e(base_url)}/repo-check'>在线扫描</a></p></div>")
    return subject, "\n".join(t), body

def run(force=False):
    base_url = os.getenv("BASE_URL", "http://127.0.0.1:8000")
    by_email = {}
    for s in db.repo_subs_verified(): by_email.setdefault(s["email"], []).append(s)
    cache, results = {}, []
    for email, ss in by_email.items():
        if not force and all(_recent(s.get("last_digest_at")) for s in ss):
            results.append({"to": email, "skipped": "本周已发送"}); continue
        rows = []
        for s in ss:
            if s["repo"] not in cache: cache[s["repo"]] = scan_safe(s["repo"])
            rows.append(cache[s["repo"]])
        subject, text, body = render(rows, ss, base_url)
        res = mailer.send(email, subject, text, html=body)
        item = {"to": email, "repos": len(rows), "ok": bool(res)}
        if not res: item["error"] = mailer.last_error
        else:
            for s in ss: db.repo_sub_update(s["id"], last_digest_at=db.now())
        results.append(item)
    return {"emails": len(by_email), "repos": len(cache), "sent": sum(1 for r in results if r.get("ok")), "results": results}
