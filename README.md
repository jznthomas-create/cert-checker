# TLS 证书检查工具（本地运行）

输入域名 → 后端 TLS 握手取证书 → 显示签发 CA、完整颁发者、生效/到期时间与剩余天数、服务器发送的证书链、信任校验结果；
若颁发者命中 `exiting_cas.json`（正在退出 SSL/TLS 业务的 CA，默认含 eMudhra、Entrust）则给出迁移步骤建议。可选查询 crt.sh 列出未过期证书。

## 运行
```bash
cd /workspace/cert-checker
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt   # 需 Python ≥ 3.13（使用 get_unverified_chain）
.venv/bin/uvicorn app:app --host 127.0.0.1 --port 8000
# 浏览器打开 http://127.0.0.1:8000
```
API：`GET /api/check?domain=github.com`（支持 `host:port`、带 http(s):// 的 URL、IDN），`GET /api/ct?domain=github.com`。

## 配置退出 CA 列表
编辑 `exiting_cas.json`：`match` 为对颁发者 O/CN（叶子及中间证书）的不区分大小写子串匹配，每次请求实时读取，无需重启。

## 错误处理
域名格式校验；DNS 解析失败、连接超时（8 秒）、拒绝连接、TLS 握手失败分别返回中文错误；证书不受信任（过期、自签等）时仍降级取证书并标注“信任校验失败”。crt.sh 超时 25 秒。

## 后续：到期邮件提醒订阅（设计）
- 数据：SQLite 表 `subscriptions(id, email, domain, threshold_days[30,14,7,1], verified, unsubscribe_token, last_notified_at, last_not_after)`。
- 订阅流程：前端填写邮箱 → 发送确认邮件（双重确认，防滥用）→ 点击链接 `verified=1`；每封邮件带一键退订链接。
- 调度：APScheduler / cron 每日运行，对去重后的域名复用 `fetch()` 检查；剩余天数跨越阈值、证书变更（序列号变化）、命中退出 CA、握手失败连续 N 次时发信；记录已发阈值避免重复。
- 发信：SMTP（自建或 SES/SendGrid 等）通过环境变量配置；限制每邮箱订阅数和请求频率。
- 可扩展：Webhook / 企业微信 / 钉钉通知，CSV 批量导入域名。

---
## v2 更新

### 安全
- **SSRF 防护**（`netguard.py`）：禁止 IP 字面量；仅允许 443 端口；解析所有 A/AAAA，任一为私有/回环/链路本地/CGNAT/保留/组播地址即拒绝（403）；连接时直连已校验的 IP（SNI 仍为域名），防 DNS rebinding。
  `RESOLVER=auto|system|doh`：auto 下若系统 DNS 返回 198.18.0.0/15 的 fake-ip（代理/沙箱环境），改用 DoH 获取真实记录做存在性和 SSRF 校验。
- **按 IP 限流**（`ratelimit.py`）：`/api/*` 每 IP 每分钟 `RATE_LIMIT_PER_MIN`（默认 20）次，超出返回 429 + Retry-After。部署在反向代理后设 `TRUST_PROXY=1` 读取 X-Forwarded-For。单进程内存实现，多实例需换 Redis。

### 到期邮件提醒（已实现）
- `POST /api/subscribe {email, domain}` → 写入 SQLite（`DB_PATH`，默认 `data/subs.db`）→ 发确认邮件；`GET /api/confirm?token=` 双重确认；`GET /api/unsubscribe?token=` 退订。
- 每日检查：`python check_expiry.py`（本地 cron：`0 9 * * * cd /path && .venv/bin/python check_expiry.py`），或 `POST /api/cron/run`（请求头 `x-cron-secret: $CRON_SECRET`）。
  规则：剩余天数跨过 30/14/7/1 天各提醒一次；已过期每天提醒；命中退出 CA 提醒一次；证书序列号变化后重置。
- 发信（`mailer.py`）：设 `RESEND_API_KEY`（+`MAIL_FROM`，需在 Resend 验证发信域名）走 Resend；否则设 `SMTP_HOST/SMTP_PORT(465或587)/SMTP_USER/SMTP_PASS/MAIL_FROM` 走 SMTP；都未设只写日志。
  本地调试可设 `DEV_EXPOSE_LINKS=1`，未配置邮件时接口直接返回确认链接。
- 其他环境变量：`BASE_URL`（邮件中链接的前缀）、`MAX_SUBS_PER_EMAIL`（默认 20）。

### 测试
```bash
.venv/bin/pip install pytest && .venv/bin/python -m pytest -q tests   # 需联网（真实域名）
```

### 部署到 Render（免费，无需信用卡）
文件：`Dockerfile`、`render.yaml`（Blueprint）、`.github/workflows/daily-check.yml`（每日触发检查）。
1. 需要一个 Git 仓库（GitHub/GitLab/Bitbucket；Render 也可直接填公开仓库 URL）。把本目录推上去。
2. 在 https://dashboard.render.com/register 用邮箱（或 GitHub/GitLab/Google）注册。
3. New → Blueprint → 选仓库（读取 `render.yaml`），或 New → Web Service → Docker，Instance Type 选 **Free**。
4. 在 Environment 填 `BASE_URL`（实际 onrender.com 地址）、`MAIL_FROM`、`RESEND_API_KEY` 或 SMTP 变量；`CRON_SECRET` 自动生成。
5. 在 GitHub 仓库 Secrets 添加 `APP_URL`、`CRON_SECRET`，Actions 每天北京时间 9:00 调用 `/api/cron/run`。
注意：免费实例 15 分钟无流量休眠（冷启动约 1 分钟）；**文件系统是临时的，重新部署/重启后 SQLite 订阅会丢失**——长期使用请把订阅换到 Render 免费 Postgres（30 天后过期）或外部免费数据库（如 Turso/Neon），或升级付费实例挂磁盘。
