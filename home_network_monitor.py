"""
Home Network Monitor
--------------------
Finds the devices on your home WiFi by "pinging" every address on the network,
shows a live table, and keeps a diary of what happens.

Features
    - Live table of devices, with nicknames like "Mom's phone"
    - Phone alerts (Telegram and/or Discord) when a device joins or leaves
    - Internet outage log, with a guess at whether the problem is your home
      or your internet provider
    - Live web dashboard: open http://localhost:8080 in your browser

Uses only Python's built-in tools, so there is nothing to install.

Run it:
    python home_network_monitor.py               (scan forever, every 30 seconds)
    python home_network_monitor.py --once        (scan one time, then stop)
    python home_network_monitor.py --interval 10 (scan every 10 seconds)
    python home_network_monitor.py --network 192.168.1.0/24  (if auto-detect guesses wrong)
    python home_network_monitor.py --router 192.168.1.254    (if your router is not the default guess)

Dashboard options:
    python home_network_monitor.py --share       (also let phones on your WiFi open the dashboard)
    python home_network_monitor.py --port 8081   (use a different port if 8080 is busy)
    python home_network_monitor.py --no-dashboard  (turn the dashboard off)

Give a device a nickname (use the IP address you see in the table):
    python home_network_monitor.py --name 192.168.1.23 "Mom's phone"

Set up and test phone alerts (see alerts.json):
    python home_network_monitor.py --test-alert

Stop it any time with Ctrl+C.
"""

import argparse
import csv
import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime

IS_WINDOWS = platform.system().lower() == "windows"
LOG_FILE = "network_log.csv"        # a diary of "joined" / "left" / "internet down" events
OUTAGE_FILE = "outage_log.csv"      # one line per internet outage: start, end, how long, likely cause
STATE_FILE = "devices.json"         # the latest snapshot of every device seen so far
NICKNAME_FILE = "nicknames.json"    # your name tags, saved by MAC address
ALERT_FILE = "alerts.json"          # your alert settings (this file holds secrets, keep it private)

INTERNET_TARGETS = ["8.8.8.8", "1.1.1.1"]   # well-known public servers we knock on to test the internet

# How to ask each kind of computer "which address is my router?", and how to read the answer.
GATEWAY_COMMANDS = [
    (["ip", "route", "show", "default"], r"default via (\d+\.\d+\.\d+\.\d+)"),
    (["route", "-n", "get", "default"], r"gateway:\s*(\d+\.\d+\.\d+\.\d+)"),
    (["route", "print", "0.0.0.0"], r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)"),
]


def get_my_network():
    """Work out which network this computer is on, for example 192.168.1.0/24."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # No data is actually sent. This just lets the OS tell us which
        # network card (and therefore which address) it would use.
        s.connect(("8.8.8.8", 80))
        my_ip = s.getsockname()[0]
    finally:
        s.close()
    return ipaddress.ip_network(f"{my_ip}/24", strict=False), my_ip


def find_router(network):
    """Find the router's address (the 'front gate' of your home network)."""
    for cmd, pattern in GATEWAY_COMMANDS:
        try:
            output = subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue
        match = re.search(pattern, output, re.MULTILINE)
        if match:
            return match.group(1)
    return str(next(network.hosts()))   # fallback guess: the first address, usually the router


# ---------------------------------------------------------------------------
# Pinging
# ---------------------------------------------------------------------------

def quick_ping(ip):
    """Knock on one address once. Returns (did_it_answer, how_many_milliseconds)."""
    ip = str(ip)
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", "1000", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=4)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False, None

    output = result.stdout
    # Windows can say "unreachable" and still exit with code 0,
    # so we also look for "TTL", which only appears in a real reply.
    online = result.returncode == 0 and "TTL=" in output.upper()

    ms = None
    if online:
        match = re.search(r"time[=<]\s*([\d.]+)\s*ms", output, re.IGNORECASE)
        if match:
            ms = float(match.group(1))
    return online, ms


def ping(ip):
    """Knock on a device, and if it answers, also ask it for its name."""
    ip = str(ip)
    online, ms = quick_ping(ip)
    name = ""
    if online:
        try:
            name = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            name = ""
    return {"ip": ip, "online": online, "ms": ms, "name": name}


def sweep(network, workers=100):
    """Ping every address on the network at the same time (fast)."""
    hosts = list(network.hosts())
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(ping, hosts))


def check_internet():
    """
    Is the internet working? We knock on two well-known servers, twice each.
    If any one answers, the internet is up. Trying several times avoids false
    alarms from one lost packet.
    """
    for _ in range(2):
        for target in INTERNET_TARGETS:
            online, ms = quick_ping(target)
            if online:
                return True, ms
    return False, None


# ---------------------------------------------------------------------------
# Nicknames
# A MAC address is a permanent ID number stamped on a device's network card,
# like a serial number. IP addresses can change, but the MAC normally stays the
# same, so nicknames are saved against the MAC.
# ---------------------------------------------------------------------------

def normalize_mac(raw):
    """Make every MAC look the same: lowercase, colons, two characters per part."""
    parts = re.split(r"[:-]", raw.strip())
    return ":".join(p.zfill(2) for p in parts).lower()


def parse_arp_output(output):
    """Pull 'IP address -> MAC address' pairs out of the text the computer gives us."""
    table = {}
    for line in output.splitlines():
        ip_match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
        mac_match = re.search(r"\b((?:[0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2})\b", line)
        if ip_match and mac_match:
            mac = normalize_mac(mac_match.group(1))
            if mac != "ff:ff:ff:ff:ff:ff":
                table[ip_match.group(1)] = mac
    return table


def read_arp_table():
    """
    Read the computer's own address book of which MAC belongs to which IP.
    Every time we ping a device, the computer quietly writes it down here.
    """
    for cmd in (["arp", "-a"], ["ip", "neigh"]):
        try:
            output = subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue
        table = parse_arp_output(output)
        if table:
            return table
    return {}


def load_nicknames():
    """Returns (nicknames, problem). 'problem' is a message if the file is broken."""
    try:
        with open(NICKNAME_FILE, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return {}, ""
    except json.JSONDecodeError:
        return {}, (f"Warning: {NICKNAME_FILE} could not be read. "
                    "Check for a missing comma or quote mark.")
    return {str(k).lower(): v for k, v in data.items()}, ""


def save_nicknames(nicknames):
    with open(NICKNAME_FILE, "w", encoding="utf-8") as f:
        json.dump(nicknames, f, indent=2, ensure_ascii=False)


def find_nickname(ip, mac, nicknames, my_ip):
    """Look for a name tag by MAC first, then by IP. Your own PC gets a default tag."""
    if mac and mac in nicknames:
        return nicknames[mac]
    if ip in nicknames:
        return nicknames[ip]
    if ip == my_ip:
        return "This PC"
    return ""


def display_label(ip, entry, nicknames, my_ip):
    """The best name we have for a device: nickname, then its own name, then 'Unknown device'."""
    return (find_nickname(ip, entry.get("mac"), nicknames, my_ip)
            or entry.get("name")
            or "Unknown device")


def name_device(ip, nickname):
    """Handles:  --name 192.168.1.23 "Mom's phone" """
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        print(f"'{ip}' does not look like an IP address. Example: 192.168.1.23")
        return

    ping(ip)  # knocking makes sure the device is in the computer's address book
    mac = read_arp_table().get(ip)

    nicknames, problem = load_nicknames()
    if problem:
        print(problem)
        print("Nothing was saved, so your existing names are safe.")
        return

    key = mac or ip
    nicknames[key] = nickname
    save_nicknames(nicknames)

    if mac:
        print(f'Saved: "{nickname}" for {mac} (currently at {ip}).')
    else:
        print(f'Saved: "{nickname}" for {ip}.')
        print("I could not read a MAC address for it. That is normal for the computer you are "
              "running this on, or for a device that is asleep, so the name is tied to the IP "
              "address instead. If that IP changes, the name will not follow.")


# ---------------------------------------------------------------------------
# Phone alerts
# ---------------------------------------------------------------------------

ALERT_TEMPLATE = {
    "telegram_token": "",
    "telegram_chat_id": "",
    "discord_webhook": "",
}


def load_alert_settings():
    """Returns (settings, problem). 'problem' is a message if the file is broken."""
    try:
        with open(ALERT_FILE, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return {}, ""
    except json.JSONDecodeError:
        return {}, (f"Warning: {ALERT_FILE} could not be read. "
                    "Check for a missing comma or quote mark.")
    return {str(k): str(v).strip() for k, v in data.items()}, ""


def configured_channels(settings):
    """Which alert channels have been filled in."""
    channels = []
    if settings.get("telegram_token") and settings.get("telegram_chat_id"):
        channels.append("Telegram")
    if settings.get("discord_webhook"):
        channels.append("Discord")
    return channels


def post_json(url, payload):
    """Send a small JSON message to a web address."""
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url, data=data,
        # Discord refuses requests that do not introduce themselves, so we add a name tag.
        headers={"Content-Type": "application/json", "User-Agent": "HomeNetworkMonitor/1.0"})
    with urllib.request.urlopen(request, timeout=10) as response:
        return response.status


def send_message(settings, text):
    """
    Send one message to every channel that is set up.
    Returns "" if at least one channel delivered it, otherwise a short problem description.
    We never print the raw error, because it could contain your secret token.
    """
    channels = configured_channels(settings)
    if not channels:
        return "No alert channel is filled in yet in alerts.json."

    delivered = False
    problems = []

    if "Telegram" in channels:
        url = f"https://api.telegram.org/bot{settings['telegram_token']}/sendMessage"
        try:
            post_json(url, {"chat_id": settings["telegram_chat_id"], "text": text})
            delivered = True
        except urllib.error.HTTPError as e:
            problems.append(f"Telegram refused the message (error {e.code}). Check the token and chat ID.")
        except (urllib.error.URLError, OSError):
            problems.append("Telegram could not be reached.")

    if "Discord" in channels:
        try:
            post_json(settings["discord_webhook"], {"content": text})
            delivered = True
        except urllib.error.HTTPError as e:
            problems.append(f"Discord refused the message (error {e.code}). Check the webhook link.")
        except (urllib.error.URLError, OSError, ValueError):
            problems.append("Discord could not be reached.")

    return "" if delivered else " ".join(problems)


class Alerter:
    """
    Collects alert messages and sends them at the end of each scan, all in one
    message so your phone does not buzz ten times. If sending fails (for example
    the internet is down), messages wait in line and go out later.
    """

    def __init__(self):
        self.settings = {}
        self.file_problem = ""
        self.send_problem = ""
        self.pending = []

    def reload(self):
        """Re-read alerts.json every scan, so edits apply without restarting."""
        self.settings, self.file_problem = load_alert_settings()

    def channels_text(self):
        names = configured_channels(self.settings)
        text = ", ".join(names) if names else "off (run --test-alert to set up)"
        if self.pending:
            text += f" ({len(self.pending)} waiting to send)"
        return text

    def queue(self, text):
        if not configured_channels(self.settings):
            return
        stamp = datetime.now().strftime("%H:%M")
        self.pending.append(f"[{stamp}] {text}")
        self.pending = self.pending[-50:]     # never let the waiting line grow forever

    def flush(self, internet_up):
        if not self.pending or not internet_up:
            return
        batch = self.pending[:30]
        problem = send_message(self.settings, "\n".join(batch))
        if problem:
            self.send_problem = problem
        else:
            self.send_problem = ""
            self.pending = self.pending[len(batch):]


def run_test_alert():
    """Handles:  --test-alert"""
    settings, problem = load_alert_settings()
    if problem:
        print(problem)
        return
    if not os.path.exists(ALERT_FILE):
        with open(ALERT_FILE, "w", encoding="utf-8") as f:
            json.dump(ALERT_TEMPLATE, f, indent=2)
        print(f"I created {ALERT_FILE} for you. Open it, fill in either the Telegram")
        print("details or the Discord link (or both), save it, then run --test-alert again.")
        print("Keep this file private. Anyone who has it can send messages as your bot.")
        return
    if not configured_channels(settings):
        print(f"{ALERT_FILE} exists but no channel is filled in yet.")
        print("For Telegram you need both telegram_token and telegram_chat_id.")
        return

    problem = send_message(settings, "Test from your Home Network Monitor. "
                                     "If you can read this on your phone, alerts work.")
    if problem:
        print("The test message did not go through:", problem)
    else:
        print("Sent! Check your phone.")


# ---------------------------------------------------------------------------
# Logging and display
# ---------------------------------------------------------------------------

def log_event(ip, event, label):
    """Add one line to the diary file."""
    new_file = not os.path.exists(LOG_FILE)
    with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if new_file:
            writer.writerow(["time", "ip", "event", "name"])
        writer.writerow([datetime.now().isoformat(timespec="seconds"), ip, event, label])


def log_outage(start, end, seconds, cause):
    """Add one line to the outage file. Written once the internet comes back."""
    new_file = not os.path.exists(OUTAGE_FILE)
    with open(OUTAGE_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if new_file:
            writer.writerow(["start", "end", "seconds", "likely_cause"])
        writer.writerow([start.isoformat(timespec="seconds"), end.isoformat(timespec="seconds"),
                         int(seconds), cause])


def format_duration(seconds):
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds} sec"
    minutes, secs = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes} min {secs} sec"
    hours, minutes = divmod(minutes, 60)
    return f"{hours} h {minutes} min"


def sort_key(ip):
    return tuple(int(part) for part in ip.split("."))


def update_devices(known, results, arp_table, nicknames, my_ip, miss_limit, alerter, baseline):
    """
    Update our list of devices from the latest scan.
    A device is only called 'left' after it misses several scans in a row, because
    phones often ignore a knock while their screen is off. 'baseline' is the very
    first scan: we log what we find but do not send alerts for it.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for r in results:
        ip = r["ip"]

        if r["online"]:
            entry = known.setdefault(ip, {"first_seen": now, "online": False, "misses": 0,
                                          "ms": None, "name": "", "mac": "", "last_seen": now})
            was_online = entry["online"]
            entry.update(online=True, misses=0, ms=r["ms"], last_seen=now,
                         name=r["name"] or entry["name"],
                         mac=arp_table.get(ip) or entry["mac"])
            if not was_online:
                label = display_label(ip, entry, nicknames, my_ip)
                log_event(ip, "joined", label)
                if not baseline and ip != my_ip:
                    alerter.queue(f"Joined: {label} ({ip})")

        elif ip in known and known[ip]["online"]:
            entry = known[ip]
            entry["misses"] += 1
            entry["ms"] = None
            if entry["misses"] >= miss_limit:
                entry["online"] = False
                label = display_label(ip, entry, nicknames, my_ip)
                log_event(ip, "left", label)
                if ip != my_ip:
                    alerter.queue(f"Left: {label} ({ip})")


def show_table(known, my_ip, network, round_number, nicknames, warnings,
               internet_text, router, alerts_text, dashboard_text):
    os.system("cls" if IS_WINDOWS else "clear")
    online_count = sum(1 for d in known.values() if d["online"])
    width = 98
    print(f"HOME NETWORK MONITOR   network: {network}   this PC: {my_ip}   router: {router}")
    print(f"Scan #{round_number} at {datetime.now().strftime('%H:%M:%S')}   "
          f"online: {online_count}   ever seen: {len(known)}")
    print(f"Internet: {internet_text}")
    print(f"Alerts: {alerts_text}")
    print(f"Dashboard: {dashboard_text}")
    print("-" * width)
    print(f"{'IP ADDRESS':<16}{'STATUS':<9}{'PING':<9}{'NICKNAME':<20}"
          f"{'MAC ADDRESS':<18}{'DEVICE NAME':<18}{'LAST SEEN'}")
    print("-" * width)
    for ip in sorted(known, key=sort_key):
        d = known[ip]
        if not d["online"]:
            status = "offline"
        elif d.get("misses", 0) > 0:
            status = "ONLINE?"     # missed a scan, waiting to see if it is really gone
        else:
            status = "ONLINE"
        ping_text = f"{d['ms']:.0f} ms" if d["ms"] is not None else "-"
        nick = find_nickname(ip, d.get("mac"), nicknames, my_ip)
        mac = d.get("mac") or "-"
        host = d.get("name") or "-"
        seen = d["last_seen"][11:]
        print(f"{ip:<16}{status:<9}{ping_text:<9}{nick[:19]:<20}"
              f"{mac:<18}{host[:17]:<18}{seen}")
    print("-" * width)
    for w in warnings:
        print(w)
    print('Name a device:  python home_network_monitor.py --name <IP> "Nickname"      Stop: Ctrl+C')


# ---------------------------------------------------------------------------
# Live dashboard
# The monitor also runs a tiny web server. Open http://localhost:8080 in your
# browser and you get a live page with the same information as the table.
# The page asks the server for fresh numbers every few seconds.
# ---------------------------------------------------------------------------

DASHBOARD = {"json": b"{}"}     # the latest snapshot, replaced after every scan

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Home Network Monitor</title>
<style>
  :root { --bg:#0e1116; --panel:#161b22; --line:#262d36; --text:#e6edf3; --muted:#8b949e;
          --green:#3fb950; --amber:#d29922; --red:#f85149; }
  * { box-sizing: border-box; }
  body { margin:0; padding:20px; background:var(--bg); color:var(--text);
         font:15px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
  .wrap { max-width:1100px; margin:0 auto; }
  header { display:flex; justify-content:space-between; align-items:flex-start; gap:12px;
           flex-wrap:wrap; margin-bottom:16px; }
  h1 { margin:0; font-size:22px; }
  h2 { margin:0 0 10px; font-size:13px; color:var(--muted); font-weight:600;
       text-transform:uppercase; letter-spacing:.05em; }
  .sub { color:var(--muted); font-size:13px; margin-top:2px; }
  .updated { color:var(--muted); font-size:13px; display:flex; align-items:center; gap:8px; }
  .pulse { width:8px; height:8px; border-radius:50%; background:var(--green); animation:pulse 2s infinite; }
  @keyframes pulse { 50% { opacity:.3; } }
  .banner { padding:10px 14px; border-radius:8px; margin-bottom:12px; font-size:14px; }
  .banner.err  { background:#3d1f1f; border:1px solid var(--red); }
  .banner.note { background:#3a2f12; border:1px solid var(--amber); }
  .stats { display:grid; grid-template-columns:repeat(auto-fit, minmax(200px, 1fr)); gap:12px; margin-bottom:16px; }
  .card, .panel { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:14px 16px; }
  .label { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.05em; }
  .value { font-size:26px; font-weight:650; margin-top:2px; }
  .value.small { font-size:16px; margin-top:8px; font-weight:600; }
  .note-text { color:var(--muted); font-size:13px; margin-top:2px; }
  .t-good { color:var(--green); } .t-bad { color:var(--red); } .t-warn { color:var(--amber); }
  .panel { margin-bottom:16px; }
  .scroll { overflow-x:auto; }
  table { width:100%; border-collapse:collapse; font-size:14px; }
  th, td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); white-space:nowrap; }
  th { color:var(--muted); font-size:12px; font-weight:600; text-transform:uppercase; letter-spacing:.05em; }
  tr:last-child td { border-bottom:0; }
  tr.off td { opacity:.55; }
  td.nick { font-weight:600; }
  td.mono { font-family:ui-monospace, Consolas, monospace; font-size:13px; }
  td.empty { color:var(--muted); white-space:normal; }
  .dot { display:inline-block; width:9px; height:9px; border-radius:50%; margin-right:8px; background:var(--muted); }
  .dot.online { background:var(--green); } .dot.checking { background:var(--amber); } .dot.offline { background:var(--red); }
  .two { display:grid; grid-template-columns:repeat(auto-fit, minmax(320px, 1fr)); gap:16px; }
  .two .panel { margin-bottom:0; }
  ul.list { list-style:none; margin:0; padding:0; }
  ul.list li { padding:7px 0; border-bottom:1px solid var(--line); font-size:14px; display:flex; gap:12px; }
  ul.list li:last-child { border-bottom:0; }
  ul.list .when { color:var(--muted); min-width:92px; font-variant-numeric:tabular-nums; }
  ul.list li.empty { color:var(--muted); }
  footer { color:var(--muted); font-size:12px; margin-top:16px; text-align:center; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <h1>Home Network Monitor</h1>
      <div class="sub" id="network">Loading...</div>
    </div>
    <div class="updated"><span class="pulse"></span><span id="updated">Waiting for the first scan...</span></div>
  </header>

  <div id="lost" class="banner err" hidden>Lost contact with the monitor. Is the script still running?</div>
  <div id="warnings"></div>

  <section class="stats">
    <div class="card"><div class="label">Devices online</div><div class="value" id="stat-online">-</div>
      <div class="note-text" id="stat-total"></div></div>
    <div class="card"><div class="label">Internet</div><div class="value" id="stat-internet">-</div>
      <div class="note-text" id="stat-internet-note"></div></div>
    <div class="card"><div class="label">Phone alerts</div><div class="value small" id="stat-alerts">-</div></div>
    <div class="card"><div class="label">Scan speed</div><div class="value small" id="stat-scan">-</div>
      <div class="note-text" id="stat-scan-note"></div></div>
  </section>

  <section class="panel">
    <h2>Devices</h2>
    <div class="scroll">
      <table>
        <thead><tr><th>Status</th><th>Nickname</th><th>IP address</th><th>Ping</th><th>MAC address</th><th>Device name</th><th>Last seen</th></tr></thead>
        <tbody id="devices"></tbody>
      </table>
    </div>
  </section>

  <div class="two">
    <section class="panel"><h2>Recent activity</h2><ul class="list" id="events"></ul></section>
    <section class="panel"><h2>Internet outages</h2><ul class="list" id="outages"></ul></section>
  </div>

  <footer>This page is served by your own computer. Nothing on it is sent to the internet.</footer>
</div>

<script>
const $ = (id) => document.getElementById(id);

// Text is always added with textContent, never as HTML. Device names come from the
// network, and this way a device with a strange name cannot inject code into the page.
function el(tag, text, cls) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = text;
  if (cls) node.className = cls;
  return node;
}
function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
function timeOf(iso) { return iso ? iso.slice(11, 19) : ""; }
function shortDateTime(iso) { return iso ? iso.slice(5, 10) + " " + iso.slice(11, 16) : ""; }
function duration(sec) {
  sec = Math.floor(Number(sec) || 0);
  if (sec < 60) return sec + " sec";
  const m = Math.floor(sec / 60);
  if (m < 60) return m + " min " + (sec % 60) + " sec";
  return Math.floor(m / 60) + " h " + (m % 60) + " min";
}
function cell(text, cls) { return el("td", text ? text : "-", cls); }

const STATUS_TEXT = { online: "Online", checking: "Checking", offline: "Offline" };

function renderDevices(list) {
  const body = $("devices");
  clear(body);
  if (list.length === 0) {
    const tr = el("tr");
    const td = el("td", "No devices seen yet. The first scan takes a few seconds.", "empty");
    td.colSpan = 7;
    tr.appendChild(td);
    body.appendChild(tr);
    return;
  }
  list.forEach((d) => {
    const tr = el("tr", null, d.status === "offline" ? "off" : "");
    const st = el("td");
    st.appendChild(el("span", "", "dot " + d.status));
    st.appendChild(document.createTextNode(STATUS_TEXT[d.status] || d.status));
    tr.appendChild(st);
    tr.appendChild(cell(d.nickname, "nick"));
    tr.appendChild(cell(d.ip, "mono"));
    tr.appendChild(cell(d.ms !== null && d.ms !== undefined ? Math.round(d.ms) + " ms" : "", ""));
    tr.appendChild(cell(d.mac, "mono"));
    tr.appendChild(cell(d.name, ""));
    tr.appendChild(cell(timeOf(d.last_seen), ""));
    body.appendChild(tr);
  });
}

function eventText(e) {
  if (e.ip === "internet") {
    return e.event === "down" ? "Internet went down (" + e.name + ")" : "Internet is back (" + e.name + ")";
  }
  const who = e.name && e.name !== e.ip ? e.name + " (" + e.ip + ")" : e.ip;
  return who + " " + e.event;
}
function eventColor(e) {
  if (e.event === "joined" || e.event === "back") return "t-good";
  if (e.event === "down") return "t-bad";
  return "t-warn";
}

function renderEvents(list) {
  const ul = $("events");
  clear(ul);
  if (list.length === 0) { ul.appendChild(el("li", "Nothing yet.", "empty")); return; }
  list.slice().reverse().forEach((e) => {
    const li = el("li");
    li.appendChild(el("span", shortDateTime(e.time), "when"));
    li.appendChild(el("span", eventText(e), eventColor(e)));
    ul.appendChild(li);
  });
}

function renderOutages(list) {
  const ul = $("outages");
  clear(ul);
  if (list.length === 0) { ul.appendChild(el("li", "No outages recorded. That is good news.", "empty")); return; }
  list.slice().reverse().forEach((o) => {
    const li = el("li");
    li.appendChild(el("span", shortDateTime(o.start), "when"));
    li.appendChild(el("span", duration(o.seconds) + ", likely cause: " + o.likely_cause));
    ul.appendChild(li);
  });
}

function render(s) {
  $("network").textContent = "Network " + s.network + "  |  router " + s.router + "  |  this PC " + s.my_ip;
  $("updated").textContent = "Updated " + s.updated + " (scan #" + s.scan + ")";

  const online = s.devices.filter((d) => d.status !== "offline").length;
  $("stat-online").textContent = online;
  $("stat-total").textContent = "of " + s.devices.length + " devices ever seen";

  const net = $("stat-internet");
  if (s.internet.up) {
    net.textContent = "OK";
    net.className = "value t-good";
    $("stat-internet-note").textContent = s.internet.ms !== null ? Math.round(s.internet.ms) + " ms to the internet" : "";
  } else {
    net.textContent = "DOWN";
    net.className = "value t-bad";
    $("stat-internet-note").textContent = "since " + s.internet.since + ", likely cause: " + s.internet.cause;
  }

  $("stat-alerts").textContent = s.alerts;
  $("stat-scan").textContent = "Every " + s.interval + " seconds";
  $("stat-scan-note").textContent = "Scan #" + s.scan;

  const warnings = $("warnings");
  clear(warnings);
  s.warnings.forEach((text) => warnings.appendChild(el("div", text, "banner note")));

  renderDevices(s.devices);
  renderEvents(s.events);
  renderOutages(s.outages);
}

async function refresh() {
  try {
    const response = await fetch("/api/status", { cache: "no-store" });
    if (!response.ok) throw new Error("bad response");
    const snapshot = await response.json();
    $("lost").hidden = true;
    if (!snapshot.devices) return;      // the first scan has not finished yet
    render(snapshot);
  } catch (error) {
    $("lost").hidden = false;
  }
}
refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>
"""


def read_csv_tail(path, count):
    """The last few rows of a CSV file, as dictionaries (empty if the file does not exist yet)."""
    try:
        with open(path, newline="", encoding="utf-8") as f:
            return list(csv.DictReader(f))[-count:]
    except OSError:
        return []


def publish_dashboard(known, nicknames, my_ip, network, router, round_number,
                      interval, internet, alerts_text, warnings):
    """Package the latest scan as JSON. The web page fetches this every few seconds."""
    devices = []
    for ip, d in known.items():
        if not d["online"]:
            status = "offline"
        elif d.get("misses", 0) > 0:
            status = "checking"
        else:
            status = "online"
        devices.append({
            "ip": ip,
            "status": status,
            "ms": d["ms"],
            "nickname": find_nickname(ip, d.get("mac"), nicknames, my_ip),
            "mac": d.get("mac") or "",
            "name": d.get("name") or "",
            "last_seen": d["last_seen"],
        })
    devices.sort(key=lambda x: (x["status"] == "offline", sort_key(x["ip"])))

    snapshot = {
        "scan": round_number,
        "updated": datetime.now().strftime("%H:%M:%S"),
        "interval": interval,
        "network": str(network),
        "router": router,
        "my_ip": my_ip,
        "internet": internet,
        "alerts": alerts_text,
        "warnings": warnings,
        "devices": devices,
        "events": read_csv_tail(LOG_FILE, 15),
        "outages": read_csv_tail(OUTAGE_FILE, 10),
    }
    DASHBOARD["json"] = json.dumps(snapshot).encode("utf-8")


class DashboardHandler(BaseHTTPRequestHandler):
    """Answers the browser: '/' gets the page, '/api/status' gets the latest numbers."""

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            body, kind = DASHBOARD_HTML.encode("utf-8"), "text/html; charset=utf-8"
        elif path == "/api/status":
            body, kind = DASHBOARD["json"], "application/json"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass    # keep the terminal table clean


class QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass    # browsers close connections all the time, so no scary error messages


def start_dashboard(host, port):
    """Start the web server in the background. Returns False if the port is already taken."""
    try:
        server = QuietServer((host, port), DashboardHandler)
    except OSError:
        return False
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return True


def main():
    parser = argparse.ArgumentParser(description="Simple home network monitor")
    parser.add_argument("--network", help="for example 192.168.1.0/24 (auto-detected if left out)")
    parser.add_argument("--router", help="your router's address (auto-detected if left out)")
    parser.add_argument("--interval", type=int, default=30, help="seconds between scans")
    parser.add_argument("--misses", type=int, default=3,
                        help="scans a device must miss in a row before it counts as 'left'")
    parser.add_argument("--once", action="store_true", help="scan one time, then stop")
    parser.add_argument("--name", nargs=2, metavar=("IP", "NICKNAME"),
                        help='give a device a nickname, e.g. --name 192.168.1.23 "Mom\'s phone"')
    parser.add_argument("--port", type=int, default=8080, help="port for the dashboard page")
    parser.add_argument("--share", action="store_true",
                        help="let phones and other devices on your WiFi open the dashboard too")
    parser.add_argument("--no-dashboard", action="store_true", help="turn the dashboard off")
    parser.add_argument("--test-alert", action="store_true",
                        help="set up alerts.json and send a test message to your phone")
    args = parser.parse_args()

    if args.test_alert:
        run_test_alert()
        return
    if args.name:
        name_device(args.name[0], args.name[1])
        return

    try:
        detected_network, my_ip = get_my_network()
    except OSError:
        detected_network, my_ip = None, ""
        if not args.network:
            print("Could not work out which network this computer is on. "
                  "Are you connected to WiFi? You can also pass --network 192.168.1.0/24")
            return

    network = ipaddress.ip_network(args.network) if args.network else detected_network
    router = args.router or find_router(network)

    known = {}          # every device we have ever seen, keyed by IP address
    alerter = Alerter()
    outage = None       # None while the internet is fine; details while it is down
    round_number = 0

    if args.no_dashboard or args.once:
        dashboard_text = "off"
    else:
        # 127.0.0.1 means "only this computer". 0.0.0.0 means "anyone on the home network".
        host = "0.0.0.0" if args.share else "127.0.0.1"
        if not start_dashboard(host, args.port):
            dashboard_text = f"could not start (port {args.port} is busy, try --port {args.port + 1})"
        elif args.share:
            dashboard_text = f"http://{my_ip}:{args.port}  (open this on your phone, on the same WiFi)"
        else:
            dashboard_text = f"http://localhost:{args.port}"

    try:
        while True:
            round_number += 1
            baseline = round_number == 1
            results = sweep(network)
            arp_table = read_arp_table()
            nicknames, nickname_problem = load_nicknames()   # re-read each scan, so edits apply live
            alerter.reload()

            # 1. Is the internet working? If not, is it our home or the provider?
            internet_up, internet_ms = check_internet()
            router_ok = True
            if not internet_up:
                router_ok = quick_ping(router)[0]

            if not internet_up and outage is None:
                if router_ok:
                    cause = "internet provider (router was fine)"
                else:
                    cause = "home network (router not answering)"
                outage = {"start": datetime.now(), "cause": cause}
                log_event("internet", "down", cause)
                # No alert yet: we cannot phone out while the internet is down.
                # A message goes out when it comes back.

            elif internet_up and outage is not None:
                end = datetime.now()
                seconds = (end - outage["start"]).total_seconds()
                log_outage(outage["start"], end, seconds, outage["cause"])
                log_event("internet", "back", f"down for {format_duration(seconds)}")
                alerter.queue(f"Internet is back. It was down for {format_duration(seconds)} "
                              f"(since {outage['start'].strftime('%H:%M')}). "
                              f"Likely cause: {outage['cause']}.")
                outage = None

            # 2. Update the device list. If the internet is down AND the router is silent,
            #    this computer has probably lost its connection (or the power is out), so
            #    the scan is unreliable. We skip it rather than call every device "left".
            if internet_up or router_ok:
                update_devices(known, results, arp_table, nicknames, my_ip,
                               args.misses, alerter, baseline)

            # 3. Send any waiting alerts (only works while the internet is up).
            alerter.flush(internet_up)

            if outage:
                internet_text = (f"DOWN since {outage['start'].strftime('%H:%M:%S')}, "
                                 f"likely cause: {outage['cause']}")
            elif internet_ms is not None:
                internet_text = f"OK ({internet_ms:.0f} ms)"
            else:
                internet_text = "OK"

            warnings = [w for w in (nickname_problem, alerter.file_problem, alerter.send_problem) if w]

            internet = {"up": internet_up, "ms": internet_ms,
                        "since": outage["start"].strftime("%H:%M:%S") if outage else None,
                        "cause": outage["cause"] if outage else None}
            publish_dashboard(known, nicknames, my_ip, network, router, round_number,
                              args.interval, internet, alerter.channels_text(), warnings)

            show_table(known, my_ip, network, round_number, nicknames, warnings,
                       internet_text, router, alerter.channels_text(), dashboard_text)

            with open(STATE_FILE, "w", encoding="utf-8") as f:
                json.dump(known, f, indent=2)

            if args.once:
                break
            time.sleep(args.interval)

    except KeyboardInterrupt:
        print("\nStopped. Your logs are in", LOG_FILE, "and", OUTAGE_FILE)


if __name__ == "__main__":
    main()