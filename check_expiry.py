"""每日检查脚本：python check_expiry.py   （cron: 0 9 * * * cd /app && python check_expiry.py）"""
import os, sys
sys.path.insert(0, os.path.dirname(__file__))
import db, mailer
from app import inspect, CheckError

BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:8000")

def run():
    subs = db.verified(); cache = {}; sent = 0
    for s in subs:
        d = s["domain"]
        if d not in cache:
            try: cache[d] = inspect(d)
            except CheckError as e: cache[d] = {"error": e.msg}
        r = cache[d]; unsub = f"{BASE_URL}/api/unsubscribe?token={s['unsub_token']}"
        if "error" in r:
            db.update(s["id"], last_checked_at=db.now(), last_error=r["error"]); continue
        leaf = r["leaf"]; days = leaf["days_left"]
        notified = set(filter(None, (s["notified_thresholds"] or "").split(",")))
        if s["last_serial"] and s["last_serial"] != leaf["serial"]:
            notified = set()  # 证书已更换，重置提醒
        msgs = []
        hit = [t for t in db.THRESHOLDS if days <= t and str(t) not in notified]
        if hit or days < 0:
            msgs.append(f"证书将在 {days} 天后到期（{leaf['not_after']}）。" if days >= 0 else f"证书已过期 {-days} 天！")
            notified |= {str(t) for t in db.THRESHOLDS if days <= t}
        if r["exiting_ca"] and "exitca" not in notified:
            msgs.append("签发 CA（" + "、".join(c["name"] for c in r["exiting_ca"]) + "）正在退出 SSL/TLS 业务，请尽快迁移：\n" +
                        "\n".join(f"{i+1}. {x}" for i, x in enumerate(r["migration_steps"])))
            notified.add("exitca")
        if msgs:
            body = f"域名：{d}\n颁发者：{leaf['issuer']}\n\n" + "\n\n".join(msgs) + f"\n\n退订：{unsub}"
            if mailer.send(s["email"], f"[证书提醒] {d} 剩余 {days} 天", body): sent += 1
        db.update(s["id"], last_checked_at=db.now(), last_error=None, last_serial=leaf["serial"],
                  last_not_after=leaf["not_after"], notified_thresholds=",".join(sorted(notified)))
    mailer.log.info("检查完成：订阅 %d 条，域名 %d 个，发送 %d 封", len(subs), len(cache), sent)
    return {"subscriptions": len(subs), "domains": len(cache), "sent": sent}

if __name__ == "__main__": run()
