# UPLC uptime monitor

Checks every UPLC site every 10 minutes from GitHub Actions and alerts Slack and email when a site goes down or comes back. Free, no third-party monitoring service.

## What it checks

| Check | When | Alert |
|---|---|---|
| Site responds (HTTPS) | every 10 min | Down / back up |
| Page is not a broken WordPress page (database error, critical error, maintenance mode, suspended hosting, parked domain, blank page) | every 10 min | Down / back up |
| Optional expected text per site (`keyword` column in `sites.csv`) | every 10 min | Down if missing |
| SSL certificate expiry | daily | ≤14 days left |
| Domain registration expiry | weekly | in weekly report (≤45 days) |

A failed site is re-checked 30 seconds later before any alert goes out, to avoid false alarms. HTTP 401/403/429 is reported as "need a look" (often a firewall blocking GitHub), not as down.

You get **one alert when a site goes down and one when it recovers**, not a message every 10 minutes. Sites that were already down at the first run are listed once in the "monitoring started" message, then in each weekly report.

## Files

- `sites.csv`: the list of sites. Add a row to add a site; set `enabled` to `no` to pause one.
- `monitor.py`: the checker (Python standard library only).
- `.github/workflows/uptime.yml`: the schedule.
- `data/status.md`: current status, updated automatically.
- `data/incidents.csv`: every outage with start, end and minutes down. Use this for the audit.
- `data/weekly/`: one report per week.

## Setup (about 15 minutes)

### 1. Upload the files
1. Create a new repository on GitHub, e.g. `uplc-uptime`. **Public** is recommended (unlimited free Actions minutes; the repo contains only domain names, no client names).
2. On the repo page: **Add file → Upload files**, drag in `monitor.py`, `sites.csv` and `README.md`, then **Commit changes**.
3. **Add file → Create new file**. In the name box type `.github/workflows/uptime.yml`, paste the content of that file, and **Commit changes**. (Creating it this way avoids the hidden-folder problem on Mac.)

### 2. Slack webhook
1. Go to https://api.slack.com/apps → **Create New App → From scratch**, name it "UPLC Uptime", pick your workspace.
2. **Incoming Webhooks** → turn on → **Add New Webhook to Workspace** → choose the channel (e.g. `#uplc-alerts`).
3. Copy the webhook URL (starts with `https://hooks.slack.com/services/...`).

### 3. Email (Gmail)
1. The sending Gmail account needs 2-Step Verification on.
2. Google Account → **Security → App passwords** → create one named "UPLC Uptime". Copy the 16-character password.

### 4. Add the secrets
Repo → **Settings → Secrets and variables → Actions → New repository secret**, one at a time:

| Name | Value |
|---|---|
| `SLACK_WEBHOOK_URL` | the Slack webhook URL |
| `SMTP_HOST` | `smtp.gmail.com` |
| `SMTP_PORT` | `465` |
| `SMTP_USER` | the sending Gmail address |
| `SMTP_PASS` | the app password |
| `ALERT_EMAIL_TO` | recipient(s), comma-separated |

### 5. Start it
Repo → **Actions** tab → enable workflows if asked → **UPLC uptime → Run workflow** (mode `check`). Within ~2 minutes you should get the "monitoring started" message in Slack and by email. After that it runs on its own.

To send a weekly report on demand: **Run workflow** with mode `digest`.

## Good to know

- GitHub can delay scheduled runs by a few minutes at busy times, so detection is within roughly 10–15 minutes.
- Private repo instead of public: free plan includes 2,000 Actions minutes/month; 10-minute checks use ~4,300. In a private repo, change `*/10` to `*/30` in the workflow.
- Times in alerts and reports are Paris time.
