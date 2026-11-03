#!/usr/bin/env python3
"""UPLC uptime monitor.

Runs on GitHub Actions. Standard library only (no installs).

Modes:
  python monitor.py check    every 10 min: up/down checks, alerts on changes,
                             SSL expiry check once a day
  python monitor.py digest   weekly: summary of uptime, down sites,
                             SSL and domain expiry

Configuration comes from environment variables (GitHub secrets):
  SLACK_WEBHOOK_URL          Slack incoming webhook
  SMTP_HOST, SMTP_PORT       e.g. smtp.gmail.com, 465
  SMTP_USER, SMTP_PASS       sending account + app password
  ALERT_EMAIL_TO             comma-separated recipients
  DRY_RUN=1                  print alerts instead of sending
"""
import concurrent.futures as cf
import csv
import datetime as dt
import json
import os
import re
import smtplib
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from email.message import EmailMessage
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SITES_FILE = ROOT / "sites.csv"
DATA = ROOT / "data"
STATE_FILE = DATA / "state.json"
INCIDENTS_FILE = DATA / "incidents.csv"
STATUS_FILE = DATA / "status.md"
WEEKLY_DIR = DATA / "weekly"

TIMEOUT = 20            # seconds per request
RETRY_DELAY = 30        # seconds before re-checking a failed site
WORKERS = 25
MAX_BODY = 400_000      # bytes read per page
SSL_WARN_DAYS = 14
DOMAIN_WARN_DAYS = 45
USER_AGENT = "Mozilla/5.0 (compatible; UPLC-Uptime-Monitor/1.0)"

# Text that means the page loads but the site is broken.
ERROR_SIGNATURES = {
    "error establishing a database connection": "WordPress database error",
    "there has been a critical error on this website": "WordPress critical error",
    "briefly unavailable for scheduled maintenance": "Stuck in WordPress maintenance mode",
    "account suspended": "Hosting account suspended",
    "this account has been suspended": "Hosting account suspended",
    "this domain has expired": "Domain expired",
    "domain has expired": "Domain expired",
    "this domain is for sale": "Parked / for-sale domain",
    "buy this domain": "Parked / for-sale domain",
    "parkingcrew": "Parked domain",
    "sedoparking": "Parked domain",
    "<title>index of /": "Directory listing instead of site",
    "fatal error</b>:": "PHP fatal error",
    "<b>fatal error</b>": "PHP fatal error",
}

try:
    from zoneinfo import ZoneInfo
    LOCAL_TZ = ZoneInfo("Europe/Paris")
except Exception:  # pragma: no cover
    LOCAL_TZ = dt.timezone.utc


def now():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def fmt(ts):
    if isinstance(ts, str):
        ts = dt.datetime.fromisoformat(ts)
    return ts.astimezone(LOCAL_TZ).strftime("%d %b %Y %H:%M")


def duration(start, end):
    secs = int((end - start).total_seconds())
    d, r = divmod(secs, 86400)
    h, r = divmod(r, 3600)
    m = r // 60
    if d:
        return f"{d}d {h}h"
    if h:
        return f"{h}h {m}m"
    return f"{max(m, 1)}m"


# ---------------------------------------------------------------- sites

def load_sites():
    sites = []
    with open(SITES_FILE, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            domain = (row.get("domain") or "").strip().lower()
            domain = re.sub(r"^https?://", "", domain).split("/")[0]
            domain = re.sub(r"^www\.", "", domain)
            if not domain or (row.get("enabled") or "yes").strip().lower() in ("no", "n", "0", "false"):
                continue
            sites.append({"domain": domain, "keyword": (row.get("keyword") or "").strip()})
    return sites


# ---------------------------------------------------------------- checks

class NoRedirectLoop(urllib.request.HTTPRedirectHandler):
    max_redirections = 8


def check_site(site):
    """Return dict(status=up|down|warn, reason, code, final_url, ms)."""
    domain = site["domain"]
    url = os.environ.get("URL_TEMPLATE", "https://{domain}/").format(domain=domain)
    opener = urllib.request.build_opener(NoRedirectLoop())
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml",
        "Cache-Control": "no-cache",
    })
    t0 = time.monotonic()
    code, body, final_url = None, b"", url
    try:
        with opener.open(req, timeout=TIMEOUT) as r:
            code = r.status
            final_url = r.geturl()
            body = r.read(MAX_BODY)
    except urllib.error.HTTPError as e:
        code = e.code
        final_url = e.geturl() or url
        try:
            body = e.read(MAX_BODY)
        except Exception:
            body = b""
    except urllib.error.URLError as e:
        reason = e.reason
        if isinstance(reason, ssl.SSLCertVerificationError):
            return _res("down", f"SSL certificate error ({reason.verify_message})", None, url, t0)
        if isinstance(reason, ssl.SSLError):
            return _res("down", f"SSL error ({reason.reason or reason})", None, url, t0)
        if isinstance(reason, socket.gaierror):
            return _res("down", "Domain does not resolve (DNS)", None, url, t0)
        if isinstance(reason, (socket.timeout, TimeoutError)):
            return _res("down", f"Timeout after {TIMEOUT}s", None, url, t0)
        if isinstance(reason, ConnectionRefusedError):
            return _res("down", "Connection refused", None, url, t0)
        return _res("down", f"Connection error ({reason})", None, url, t0)
    except (socket.timeout, TimeoutError):
        return _res("down", f"Timeout after {TIMEOUT}s", None, url, t0)
    except Exception as e:  # noqa: BLE001
        return _res("down", f"Error ({type(e).__name__}: {e})", None, url, t0)

    if code in (401, 403, 429):
        return _res("warn", f"HTTP {code} (blocked or protected; may be a firewall)", code, final_url, t0)
    if code >= 400:
        return _res("down", f"HTTP {code}", code, final_url, t0)

    text = body.decode("utf-8", "ignore").lower()
    for sig, label in ERROR_SIGNATURES.items():
        if sig in text:
            return _res("down", label, code, final_url, t0)
    visible = re.sub(r"<[^>]+>", " ", re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", text))
    if len(visible.split()) < 5 and "<script" not in text:
        return _res("down", "Blank page", code, final_url, t0)
    if site["keyword"] and site["keyword"].lower() not in text:
        return _res("down", f"Expected text '{site['keyword']}' missing", code, final_url, t0)

    res = _res("up", "OK", code, final_url, t0)
    final_host = re.sub(r"^www\.", "", urllib.parse.urlparse(final_url).hostname or "")
    if final_host and final_host != domain:
        res["note"] = f"redirects to {final_host}"
    return res


def _res(status, reason, code, final_url, t0):
    return {"status": status, "reason": reason, "code": code,
            "final_url": final_url, "ms": int((time.monotonic() - t0) * 1000)}


def run_checks(sites):
    results = {}
    with cf.ThreadPoolExecutor(WORKERS) as ex:
        for site, res in zip(sites, ex.map(check_site, sites)):
            results[site["domain"]] = res
    failed = [s for s in sites if results[s["domain"]]["status"] == "down"]
    if failed:
        time.sleep(RETRY_DELAY)  # confirm before alerting
        with cf.ThreadPoolExecutor(WORKERS) as ex:
            for site, res in zip(failed, ex.map(check_site, failed)):
                results[site["domain"]] = res
    return results


def ssl_days_left(domain):
    """Days until the site's SSL certificate expires (None if unreadable)."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as s:
                cert = s.getpeercert()
        expires = dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), dt.timezone.utc)
        return (expires - now()).days, expires
    except Exception:
        return None, None


def domain_expiry(domain):
    """Look up registration expiry via RDAP (public, free)."""
    try:
        req = urllib.request.Request(f"https://rdap.org/domain/{domain}",
                                     headers={"User-Agent": USER_AGENT, "Accept": "application/rdap+json"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            data = json.load(r)
        for ev in data.get("events", []):
            if ev.get("eventAction") == "expiration":
                exp = dt.datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                return (exp - now()).days, exp
    except Exception:
        pass
    return None, None


# ---------------------------------------------------------------- state

def load_state():
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {"_meta": {}, "sites": {}}


def save_state(state):
    DATA.mkdir(exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=1, sort_keys=True) + "\n")


def log_incident(domain, start, end, reason):
    new = not INCIDENTS_FILE.exists()
    with open(INCIDENTS_FILE, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if new:
            w.writerow(["domain", "down_at_utc", "up_at_utc", "minutes_down", "reason"])
        mins = int((dt.datetime.fromisoformat(end) - dt.datetime.fromisoformat(start)).total_seconds() // 60)
        w.writerow([domain, start, end, mins, reason])


def write_status(state):
    sites = state["sites"]
    down = sorted((d, s) for d, s in sites.items() if s["status"] == "down")
    warn = sorted((d, s) for d, s in sites.items() if s["status"] == "warn")
    up = sum(1 for s in sites.values() if s["status"] == "up")
    lines = ["# UPLC site status", "",
             f"**{up} up · {len(down)} down · {len(warn)} need a look** (of {len(sites)})", ""]
    if down:
        lines += ["## Down", "", "| Site | Since (Paris) | Reason |", "|---|---|---|"]
        lines += [f"| {d} | {fmt(s['since'])} | {s['reason']} |" for d, s in down]
        lines.append("")
    if warn:
        lines += ["## Need a look", "", "| Site | Since (Paris) | Reason |", "|---|---|---|"]
        lines += [f"| {d} | {fmt(s['since'])} | {s['reason']} |" for d, s in warn]
        lines.append("")
    STATUS_FILE.write_text("\n".join(lines))


# ---------------------------------------------------------------- notify

def notify(subject, text, slack_text=None):
    slack_text = slack_text or f"*{subject}*\n{text}"
    if os.environ.get("DRY_RUN"):
        print(f"\n===== ALERT: {subject}\n{text}\n")
        return
    hook = os.environ.get("SLACK_WEBHOOK_URL")
    if hook:
        try:
            req = urllib.request.Request(hook, data=json.dumps({"text": slack_text}).encode(),
                                         headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=20).read()
        except Exception as e:  # noqa: BLE001
            print(f"Slack failed: {e}", file=sys.stderr)
    host, user, pw = (os.environ.get(k) for k in ("SMTP_HOST", "SMTP_USER", "SMTP_PASS"))
    to = os.environ.get("ALERT_EMAIL_TO")
    if host and user and pw and to:
        port = int(os.environ.get("SMTP_PORT") or 465)
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = f"UPLC Uptime <{user}>"
        msg["To"] = to
        msg.set_content(text.replace("*", ""))
        try:
            if port == 465:
                with smtplib.SMTP_SSL(host, port, timeout=30) as s:
                    s.login(user, pw)
                    s.send_message(msg)
            else:
                with smtplib.SMTP(host, port, timeout=30) as s:
                    s.starttls()
                    s.login(user, pw)
                    s.send_message(msg)
        except Exception as e:  # noqa: BLE001
            print(f"Email failed: {e}", file=sys.stderr)


# ---------------------------------------------------------------- modes

def mode_check():
    sites = load_sites()
    state = load_state()
    first_run = not state["sites"]
    results = run_checks(sites)
    ts = now().isoformat()
    went_down, recovered = [], []

    for domain, res in results.items():
        prev = state["sites"].get(domain)
        if prev is None or prev["status"] != res["status"]:
            if prev and prev["status"] == "down":
                log_incident(domain, prev["since"], ts, prev["reason"])
                recovered.append((domain, duration(dt.datetime.fromisoformat(prev["since"]), now())))
            if res["status"] == "down" and prev is not None:
                went_down.append((domain, res["reason"]))
            state["sites"][domain] = {"status": res["status"], "since": ts, "reason": res["reason"]}
        elif res["status"] != "up" and res["reason"] != prev["reason"]:
            state["sites"][domain]["reason"] = res["reason"]
        if res.get("note"):
            state["sites"][domain]["note"] = res["note"]
        else:
            state["sites"][domain].pop("note", None)

    # Sites removed from sites.csv
    for domain in set(state["sites"]) - set(results):
        del state["sites"][domain]

    if first_run:
        down = sorted((d, r["reason"]) for d, r in results.items() if r["status"] == "down")
        warn = sorted((d, r["reason"]) for d, r in results.items() if r["status"] == "warn")
        body = [f"Monitoring started for {len(results)} UPLC sites.",
                f"{len(results) - len(down) - len(warn)} up, {len(down)} down, {len(warn)} need a look.",
                "From now on you'll get an alert when a site goes down or comes back.", ""]
        if down:
            body += ["Already down at the first check:"] + [f"- {d}: {r}" for d, r in down] + [""]
        if warn:
            body += ["Need a look (blocked or protected):"] + [f"- {d}: {r}" for d, r in warn]
        notify("UPLC uptime: monitoring started", "\n".join(body))
    else:
        if went_down:
            lines = [f"🔴 {d} is DOWN: {r}\n   https://{d}" for d, r in went_down]
            subj = (f"🔴 DOWN: {went_down[0][0]}" if len(went_down) == 1
                    else f"🔴 {len(went_down)} UPLC sites DOWN")
            if len(went_down) >= 5:
                lines.insert(0, "Many sites failed at once: likely a hosting or network problem, not the sites themselves.\n")
            notify(subj, "\n".join(lines) + f"\n\nChecked {fmt(ts)} (Paris time).")
        if recovered:
            lines = [f"✅ {d} is back UP (was down {dur})" for d, dur in recovered]
            subj = (f"✅ UP: {recovered[0][0]}" if len(recovered) == 1
                    else f"✅ {len(recovered)} UPLC sites back up")
            notify(subj, "\n".join(lines))

    # SSL expiry, once a day
    today = now().date().isoformat()
    if state["_meta"].get("ssl_checked") != today:
        state["_meta"]["ssl_checked"] = today
        live = [d for d, s in state["sites"].items() if s["status"] != "down"]
        with cf.ThreadPoolExecutor(WORKERS) as ex:
            ssl_res = dict(zip(live, ex.map(ssl_days_left, live)))
        expiring = sorted((days, d) for d, (days, _) in ssl_res.items()
                          if days is not None and days <= SSL_WARN_DAYS)
        state["_meta"]["ssl"] = {d: days for d, (days, _) in ssl_res.items() if days is not None}
        if expiring:
            lines = [f"🔒 {d}: SSL certificate expires in {days} days" if days >= 0
                     else f"🔒 {d}: SSL certificate EXPIRED {-days} days ago" for days, d in expiring]
            notify(f"🔒 {len(expiring)} UPLC SSL certificate(s) expiring soon",
                   "\n".join(lines) + "\n\nUsually means auto-renewal failed at the host.")

    save_state(state)
    write_status(state)
    print(f"Checked {len(results)} sites: "
          f"{sum(r['status'] == 'up' for r in results.values())} up, "
          f"{sum(r['status'] == 'down' for r in results.values())} down, "
          f"{sum(r['status'] == 'warn' for r in results.values())} warn")


def uptime_last_days(days=7):
    """Downtime minutes per domain over the last N days (closed + open incidents)."""
    end = now()
    start = end - dt.timedelta(days=days)
    downtime = {}

    def add(domain, a, b):
        a, b = max(a, start), min(b, end)
        if b > a:
            downtime[domain] = downtime.get(domain, 0) + (b - a).total_seconds() / 60

    if INCIDENTS_FILE.exists():
        with open(INCIDENTS_FILE, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                add(row["domain"], dt.datetime.fromisoformat(row["down_at_utc"]),
                    dt.datetime.fromisoformat(row["up_at_utc"]))
    for domain, s in load_state()["sites"].items():
        if s["status"] == "down":
            add(domain, dt.datetime.fromisoformat(s["since"]), end)
    return downtime


def mode_digest():
    state = load_state()
    sites = state["sites"]
    total = len(sites)
    if not total:
        print("No state yet; run 'check' first.")
        return
    period_min = 7 * 24 * 60
    downtime = uptime_last_days(7)
    week_ago = now() - dt.timedelta(days=7)
    # Sites down for the whole week (often never launched) are listed separately
    # so they don't drag the average of the live portfolio.
    down_all_week = {d for d, s in sites.items()
                     if s["status"] == "down" and dt.datetime.fromisoformat(s["since"]) <= week_ago}
    live = [d for d in sites if d not in down_all_week]
    overall = (100 * (1 - sum(downtime.get(d, 0) for d in live) / (period_min * len(live)))
               if live else 0.0)

    down = sorted((d, s) for d, s in sites.items() if s["status"] == "down")
    warn = sorted((d, s) for d, s in sites.items() if s["status"] == "warn")
    redirects = sorted((d, s["note"]) for d, s in sites.items() if s.get("note"))
    worst = sorted(((m, d) for d, m in downtime.items()
                    if d in sites and d not in down_all_week and m >= 1), reverse=True)[:10]

    ssl_soon = sorted((days, d) for d, days in state["_meta"].get("ssl", {}).items() if days <= 30)

    names = [d for d in sites]
    with cf.ThreadPoolExecutor(10) as ex:
        dom = dict(zip(names, ex.map(domain_expiry, names)))
    dom_soon = sorted((days, d, exp) for d, (days, exp) in dom.items()
                      if days is not None and days <= DOMAIN_WARN_DAYS)
    unknown_dom = sum(1 for days, _ in dom.values() if days is None)

    week = now().date().isoformat()
    L = [f"UPLC weekly uptime report: week ending {now().astimezone(LOCAL_TZ):%d %b %Y}", "",
         f"Sites monitored: {total}",
         f"Average uptime (7 days, {len(live)} live sites): {overall:.2f}%",
         f"Down right now: {len(down)} (of which {len(down_all_week)} down all week)"
         f"  ·  Need a look: {len(warn)}", ""]
    if down:
        L += ["DOWN NOW"] + [f"- {d}: {s['reason']} (since {fmt(s['since'])})" for d, s in down] + [""]
    if worst:
        L += ["MOST DOWNTIME THIS WEEK (excluding sites down all week)"]
        L += [f"- {d}: {100 * (1 - m / period_min):.2f}% uptime ({int(m)} min down)" for m, d in worst] + [""]
    if ssl_soon:
        L += ["SSL CERTIFICATES EXPIRING ≤30 DAYS"] + [f"- {d}: {days} days" for days, d in ssl_soon] + [""]
    if dom_soon:
        L += [f"DOMAINS EXPIRING ≤{DOMAIN_WARN_DAYS} DAYS"]
        L += [f"- {d}: {days} days ({exp:%d %b %Y})" for days, d, exp in dom_soon] + [""]
    if unknown_dom:
        L += [f"(Registration expiry not available for {unknown_dom} domains.)", ""]
    if warn:
        L += ["NEED A LOOK (blocked/protected, not counted as down)"]
        L += [f"- {d}: {s['reason']}" for d, s in warn] + [""]
    if redirects:
        L += ["REDIRECT TO ANOTHER DOMAIN (check this is intended)"]
        L += [f"- {d}: {n}" for d, n in redirects] + [""]
    text = "\n".join(L)

    WEEKLY_DIR.mkdir(parents=True, exist_ok=True)
    (WEEKLY_DIR / f"{week}.md").write_text(text + "\n")
    slack = (f"*UPLC weekly uptime*: {overall:.2f}% avg · {len(down)} down now · "
             f"{len(ssl_soon)} SSL ≤30d · {len(dom_soon)} domains ≤{DOMAIN_WARN_DAYS}d\n```" + text + "```")
    notify(f"UPLC weekly uptime: {overall:.2f}% · {len(down)} down", text, slack)
    print(text)


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "check"
    {"check": mode_check, "digest": mode_digest}[mode]()
