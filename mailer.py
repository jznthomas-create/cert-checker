"""邮件发送：优先 Resend API，其次 SMTP，均未配置时只写日志。"""
import logging, os, smtplib, ssl
from email.message import EmailMessage
import httpx

log = logging.getLogger("mailer")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

def mode():
    if os.getenv("RESEND_API_KEY"): return "resend"
    if os.getenv("SMTP_HOST"): return "smtp"
    return "log"

def send(to: str, subject: str, body: str) -> bool:
    sender = os.getenv("MAIL_FROM", "cert-checker@localhost")
    m = mode()
    try:
        if m == "resend":
            r = httpx.post("https://api.resend.com/emails", timeout=15,
                           headers={"Authorization": f"Bearer {os.environ['RESEND_API_KEY']}"},
                           json={"from": sender, "to": [to], "subject": subject, "text": body})
            r.raise_for_status()
        elif m == "smtp":
            msg = EmailMessage(); msg["From"], msg["To"], msg["Subject"] = sender, to, subject; msg.set_content(body)
            port = int(os.getenv("SMTP_PORT", "465")); host = os.environ["SMTP_HOST"]
            if port == 465: s = smtplib.SMTP_SSL(host, port, context=ssl.create_default_context(), timeout=20)
            else: s = smtplib.SMTP(host, port, timeout=20); s.starttls(context=ssl.create_default_context())
            with s:
                if os.getenv("SMTP_USER"): s.login(os.environ["SMTP_USER"], os.getenv("SMTP_PASS", ""))
                s.send_message(msg)
        else:
            log.info("[未配置邮件，仅记录] To=%s Subject=%s\n%s", to, subject, body)
        log.info("邮件已处理 mode=%s to=%s subject=%s", m, to, subject)
        return True
    except Exception as e:
        log.error("邮件发送失败 mode=%s to=%s: %s", m, to, e); return False
