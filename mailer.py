"""邮件发送：优先 Resend API，其次 SMTP，均未配置时只写日志。"""
import logging, os, smtplib, ssl
from email.message import EmailMessage
import httpx

log = logging.getLogger("mailer")
last_error = None
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

def mode():
    if os.getenv("RESEND_API_KEY"): return "resend"
    if os.getenv("SMTP_HOST"): return "smtp"
    return "log"

def send(to: str, subject: str, body: str, html: str | None = None):
    """成功返回真值（Resend 时为邮件 id），失败返回 False。"""
    sender = os.getenv("MAIL_FROM", "cert-checker@localhost")
    global last_error
    m = mode(); result = True; last_error = None
    try:
        if m == "resend":
            r = httpx.post("https://api.resend.com/emails", timeout=15,
                           headers={"Authorization": f"Bearer {os.environ['RESEND_API_KEY']}"},
                           json={"from": sender, "to": [to], "subject": subject, "text": body, **({"html": html} if html else {})})
            if r.status_code >= 400:
                last_error = f"Resend {r.status_code}: {r.text[:200]}"
                log.error("Resend 拒绝 %s", last_error); return False
            result = (r.json() or {}).get("id") or True
        elif m == "smtp":
            msg = EmailMessage(); msg["From"], msg["To"], msg["Subject"] = sender, to, subject; msg.set_content(body)
            if html: msg.add_alternative(html, subtype="html")
            port = int(os.getenv("SMTP_PORT", "465")); host = os.environ["SMTP_HOST"]
            if port == 465: s = smtplib.SMTP_SSL(host, port, context=ssl.create_default_context(), timeout=20)
            else: s = smtplib.SMTP(host, port, timeout=20); s.starttls(context=ssl.create_default_context())
            with s:
                if os.getenv("SMTP_USER"): s.login(os.environ["SMTP_USER"], os.getenv("SMTP_PASS", ""))
                s.send_message(msg)
        else:
            log.info("[未配置邮件，仅记录] To=%s Subject=%s\n%s", to, subject, body)
        log.info("邮件已处理 mode=%s to=%s subject=%s id=%s", m, to, subject, result)
        return result
    except Exception as e:
        last_error = f"{type(e).__name__}: {e}"[:200]
        log.error("邮件发送失败 mode=%s to=%s: %s", m, to, e); return False
