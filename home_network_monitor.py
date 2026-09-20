import argparse
import csv
import ipaddress
import json
import os
import platform
import re
import socket
import sqlite3
import subprocess
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime, timedelta

IS_WINDOWS = platform.system().lower() == "windows"
LOG_FILE = "network_log.csv"
OUTAGE_FILE = "outage_log.csv"
STATE_FILE = "devices.json"
NICKNAME_FILE = "nicknames.json"
ALERT_FILE = "alerts.json"
HISTORY_FILE = "history.db"
APPROVED_FILE = "approved.json"
ALARM_COOLDOWN = 6 * 3600

INTERNET_KEY = "__internet__"
ROUTER_KEY = "__router__"
SUMMARY_DAYS = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]
BUCKET_SECONDS = 1800
BUCKET_COUNT = 48

INTERNET_TARGETS = ["8.8.8.8", "1.1.1.1"]

GATEWAY_COMMANDS = [
    (["ip", "route", "show", "default"], r"default via (\d+\.\d+\.\d+\.\d+)"),
    (["route", "-n", "get", "default"], r"gateway:\s*(\d+\.\d+\.\d+\.\d+)"),
    (["route", "print", "0.0.0.0"], r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)"),
]


def get_my_network():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        my_ip = s.getsockname()[0]
    finally:
        s.close()
    return ipaddress.ip_network(f"{my_ip}/24", strict=False), my_ip


def find_router(network):
    for cmd, pattern in GATEWAY_COMMANDS:
        try:
            output = subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue
        match = re.search(pattern, output, re.MULTILINE)
        if match:
            return match.group(1)
    return str(next(network.hosts()))


def quick_ping(ip):
    ip = str(ip)
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", "1000", ip]
    elif platform.system().lower() == "darwin":
        cmd = ["ping", "-c", "1", "-W", "1000", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=4)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False, None

    output = result.stdout
    online = result.returncode == 0 and "TTL=" in output.upper()

    ms = None
    if online:
        match = re.search(r"time[=<]\s*([\d.]+)\s*ms", output, re.IGNORECASE)
        if match:
            ms = float(match.group(1))
    return online, ms


def ping(ip):
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
    hosts = list(network.hosts())
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(ping, hosts))


def check_internet():
    for _ in range(2):
        for target in INTERNET_TARGETS:
            online, ms = quick_ping(target)
            if online:
                return True, ms
    return False, None


def parse_burst(output, count):
    times = []
    for line in output.splitlines():
        if "ttl=" in line.lower():
            match = re.search(r"time[=<]\s*([\d.]+)\s*ms", line, re.IGNORECASE)
            if match:
                times.append(float(match.group(1)))
    times = times[:count]
    received = len(times)
    jitter = None
    if received >= 2:
        gaps = [abs(b - a) for a, b in zip(times, times[1:])]
        jitter = round(sum(gaps) / len(gaps), 2)
    return {
        "sent": count,
        "received": received,
        "loss": round(100.0 * (count - received) / count, 1),
        "min": min(times) if times else None,
        "avg": round(sum(times) / received, 2) if times else None,
        "max": max(times) if times else None,
        "jitter": jitter,
    }


def ping_burst(ip, count):
    ip = str(ip)
    system = platform.system().lower()
    if IS_WINDOWS:
        cmd = ["ping", "-n", str(count), "-w", "1000", ip]
    elif system == "darwin":
        cmd = ["ping", "-c", str(count), "-W", "1000", ip]
    else:
        cmd = ["ping", "-c", str(count), "-i", "0.2", "-W", "1", ip]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=count * 2 + 10)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    return parse_burst(result.stdout, count)


def quality_verdict(loss, jitter):
    if loss is None:
        return "no data yet"
    jitter = jitter if jitter is not None else 0
    if loss <= 1 and jitter <= 20:
        return "Good"
    if loss <= 3 and jitter <= 50:
        return "Fair"
    return "Poor"


class QualityWatcher:
    WINDOW = 6
    BAD_LOSS, BAD_JITTER = 5.0, 50.0
    OK_LOSS, OK_JITTER = 2.0, 30.0
    COOLDOWN = 1800

    def __init__(self):
        self.windows = {INTERNET_KEY: deque(maxlen=self.WINDOW), ROUTER_KEY: deque(maxlen=self.WINDOW)}
        self.poor_since = {}
        self.last_alert = {}

    def numbers(self, key):
        window = self.windows[key]
        if len(window) < self.WINDOW:
            return None
        sent = sum(b["sent"] for b in window)
        received = sum(b["received"] for b in window)
        jitters = [b["jitter"] for b in window if b["jitter"] is not None]
        loss = 100.0 * (sent - received) / sent if sent else 0.0
        return loss, (sum(jitters) / len(jitters) if jitters else 0.0)

    def is_bad(self, key):
        n = self.numbers(key)
        return n is not None and (n[0] > self.BAD_LOSS or n[1] > self.BAD_JITTER)

    def update(self, quality, internet_up, trusted, alerter):
        if not trusted:
            for window in self.windows.values():
                window.clear()
            return
        if not internet_up:
            self.windows[INTERNET_KEY].clear()

        for key, burst in quality.items():
            if burst and not (key == INTERNET_KEY and not internet_up):
                self.windows[key].append(burst)

        for key in (ROUTER_KEY, INTERNET_KEY):
            numbers = self.numbers(key)
            if numbers is None:
                continue
            loss, jitter = numbers
            name = "the internet" if key == INTERNET_KEY else "your router"
            short = "internet" if key == INTERNET_KEY else "router"
            detail = f"{loss:.0f}% of test pings lost, jitter {jitter:.0f} ms"

            if key in self.poor_since:
                if loss <= self.OK_LOSS and jitter <= self.OK_JITTER:
                    seconds = (datetime.now() - self.poor_since.pop(key)).total_seconds()
                    log_event(short, "recovered", detail)
                    alerter.queue(f"Connection to {name} is back to normal after {format_duration(seconds)}.")
            elif (loss > self.BAD_LOSS or jitter > self.BAD_JITTER) \
                    and time.time() - self.last_alert.get(key, 0) > self.COOLDOWN:
                self.poor_since[key] = datetime.now()
                self.last_alert[key] = time.time()
                log_event(short, "poor", detail)
                if key == ROUTER_KEY:
                    hint = "Your WiFi or router may be struggling (weak signal, crowding or interference)."
                elif ROUTER_KEY in self.poor_since or self.is_bad(ROUTER_KEY):
                    hint = "Your router looks affected too, so check your WiFi and router."
                else:
                    hint = "Your router looks fine, so the problem is probably your internet provider."
                alerter.queue(f"Poor connection to {name}: {detail} over the last few minutes. {hint}")


def normalize_mac(raw):
    parts = re.split(r"[:-]", raw.strip())
    return ":".join(p.zfill(2) for p in parts).lower()


def parse_arp_output(output):
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
    if mac and mac in nicknames:
        return nicknames[mac]
    if ip in nicknames:
        return nicknames[ip]
    if ip == my_ip:
        return "This PC"
    return ""


def display_label(ip, entry, nicknames, my_ip):
    return (find_nickname(ip, entry.get("mac"), nicknames, my_ip)
            or entry.get("name")
            or "Unknown device")


def name_device(ip, nickname):
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        print(f"'{ip}' does not look like an IP address. Example: 192.168.1.23")
        return

    ping(ip)
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


def load_approved():
    try:
        with open(APPROVED_FILE, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("not a dictionary")
    except FileNotFoundError:
        return None, ""
    except (json.JSONDecodeError, ValueError):
        return None, (f"Warning: {APPROVED_FILE} could not be read, so the stranger alarm is paused. "
                      "Check for a missing comma or quote mark.")
    return {str(k).lower(): str(v) for k, v in data.items()}, ""


def save_approved(approved):
    with open(APPROVED_FILE, "w", encoding="utf-8") as f:
        json.dump(approved, f, indent=2, ensure_ascii=False)


def is_stranger(ip, entry, approved, my_ip):
    if approved is None or ip == my_ip:
        return False
    return device_key(ip, entry) not in approved and ip not in approved


def trust_of(ip, entry, approved, my_ip):
    if approved is None:
        return None
    return "unknown" if is_stranger(ip, entry, approved, my_ip) else "approved"


def run_approve(targets):
    known = load_known()
    if not known:
        print("No devices have been seen yet. Run the monitor for a minute first, then try again.")
        return
    approved, problem = load_approved()
    if problem:
        print(problem)
        print("Nothing was changed, so your existing approvals are safe.")
        return
    if approved is None:
        approved = {}
    nicknames, nickname_problem = load_nicknames()
    try:
        my_ip = get_my_network()[1]
    except OSError:
        my_ip = ""

    def best_name(ip):
        d = known[ip]
        return find_nickname(ip, d.get("mac"), nicknames, my_ip) or d.get("name") or "Unknown device"

    def label_for_file(ip):
        name = best_name(ip)
        return name if name != "Unknown device" else f"device at {ip} when approved"

    if targets:
        for ip in targets:
            if ip not in known:
                print(f"{ip}: I have not seen that address yet, so I skipped it.")
                continue
            approved[device_key(ip, known[ip])] = label_for_file(ip)
            print(f"Approved: {best_name(ip)} ({ip})")
        save_approved(approved)
        return

    pending = [ip for ip in sorted(known, key=sort_key)
               if ip != my_ip and device_key(ip, known[ip]) not in approved and ip not in approved]
    if not pending:
        save_approved(approved)
        print("Every device I know about is already approved. The stranger alarm is on.")
        return

    print(f"{len(pending)} device(s) to review. Only approve devices you recognize.")
    print("Anything you leave as unknown will trigger an alarm when it joins the network.\n")
    approve_rest = False
    new_names = {}
    try:
        for number, ip in enumerate(pending, 1):
            d = known[ip]
            key = device_key(ip, d)
            print(f"[{number}/{len(pending)}] {ip}")
            print(f"    nickname: {best_name(ip) if best_name(ip) != 'Unknown device' else '-'}"
                  f"   device name: {d.get('name') or '-'}")
            print(f"    MAC address: {d.get('mac') or '(not available)'}   last seen: {d.get('last_seen') or '-'}")
            if approve_rest:
                answer = "y"
            else:
                answer = input("    Do you recognize it? y = approve, a = approve all the rest, "
                               "q = save and quit, anything else = leave as unknown: ").strip().lower()
            if answer == "q":
                break
            if answer == "a":
                approve_rest = True
                answer = "y"
            if answer == "y":
                approved[key] = label_for_file(ip)
                if not approve_rest and best_name(ip) == "Unknown device" and not nickname_problem:
                    name = input("    Nickname for it (press Enter to skip): ").strip()
                    if name:
                        new_names[key] = name
                        approved[key] = name
                print("    Approved.\n")
            else:
                print("    Left as unknown.\n")
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled. Nothing was saved.")
        return

    save_approved(approved)
    if new_names:
        nicknames.update(new_names)
        save_nicknames(nicknames)
    print(f"Saved. {len(approved)} approved device(s). The stranger alarm is on.")


def run_unapprove(targets):
    approved, problem = load_approved()
    if problem:
        print(problem)
        print("Nothing was changed.")
        return
    if approved is None:
        print("The stranger alarm is not set up yet, so there is nothing to remove.")
        return
    known = load_known()
    for target in targets:
        keys = {target.lower()}
        if target in known:
            keys.add(device_key(target, known[target]))
        removed = [k for k in keys if approved.pop(k, None) is not None]
        print(f"Removed {target} from the approved list." if removed else f"{target} was not on the approved list.")
    save_approved(approved)


ALERT_TEMPLATE = {
    "telegram_token": "",
    "telegram_chat_id": "",
    "discord_webhook": "",
}


def load_alert_settings():
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
    channels = []
    if settings.get("telegram_token") and settings.get("telegram_chat_id"):
        channels.append("Telegram")
    if settings.get("discord_webhook"):
        channels.append("Discord")
    return channels


def post_json(url, payload):
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json", "User-Agent": "HomeNetworkMonitor/1.0"})
    with urllib.request.urlopen(request, timeout=10) as response:
        return response.status


def send_message(settings, text):
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
    def __init__(self):
        self.settings = {}
        self.file_problem = ""
        self.send_problem = ""
        self.pending = []

    def reload(self):
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
        self.pending = self.pending[-50:]

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


def log_event(ip, event, label):
    new_file = not os.path.exists(LOG_FILE)
    with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if new_file:
            writer.writerow(["time", "ip", "event", "name"])
        writer.writerow([datetime.now().isoformat(timespec="seconds"), ip, event, label])


def log_outage(start, end, seconds, cause):
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


def update_devices(known, results, arp_table, nicknames, my_ip, miss_limit, alerter, baseline,
                   approved, alarm_times):
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
                if is_stranger(ip, entry, approved, my_ip):
                    key = device_key(ip, entry)
                    if time.time() - alarm_times.get(key, 0) > ALARM_COOLDOWN:
                        alarm_times[key] = time.time()
                        log_event(ip, "stranger", label)
                        alerter.queue(f"UNKNOWN DEVICE joined: {label} ({ip}, MAC {entry['mac'] or 'not available'}). "
                                      f"If it is yours, approve it with: python home_network_monitor.py --approve {ip}")
                elif not baseline and ip != my_ip:
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
               internet_text, router, alerts_text, dashboard_text, approved, quality_text):
    os.system("cls" if IS_WINDOWS else "clear")
    online_count = sum(1 for d in known.values() if d["online"])
    width = 98
    print(f"HOME NETWORK MONITOR   network: {network}   this PC: {my_ip}   router: {router}")
    print(f"Scan #{round_number} at {datetime.now().strftime('%H:%M:%S')}   "
          f"online: {online_count}   ever seen: {len(known)}")
    print(f"Internet: {internet_text}")
    print(f"Quality: {quality_text}")
    print(f"Alerts: {alerts_text}")
    if approved is None:
        print("Stranger alarm: off (run  python home_network_monitor.py --approve  to turn it on)")
    else:
        strangers = sum(1 for ip, d in known.items() if d["online"] and is_stranger(ip, d, approved, my_ip))
        print(f"Stranger alarm: ON, {len(approved)} approved device(s), {strangers} unapproved online now")
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
            status = "ONLINE?"
        else:
            status = "ONLINE"
        ping_text = f"{d['ms']:.0f} ms" if d["ms"] is not None else "-"
        nick = find_nickname(ip, d.get("mac"), nicknames, my_ip)
        mac = d.get("mac") or "-"
        host = d.get("name") or "-"
        seen = d["last_seen"][11:]
        flag = "  NOT APPROVED" if d["online"] and is_stranger(ip, d, approved, my_ip) else ""
        print(f"{ip:<16}{status:<9}{ping_text:<9}{nick[:19]:<20}"
              f"{mac:<18}{host[:17]:<18}{seen}{flag}")
    print("-" * width)
    for w in warnings:
        print(w)
    print('Name a device:  python home_network_monitor.py --name <IP> "Nickname"      Stop: Ctrl+C')


def open_history():
    conn = sqlite3.connect(HISTORY_FILE, timeout=10)
    conn.execute("CREATE TABLE IF NOT EXISTS samples (ts INTEGER, key TEXT, online INTEGER, ms REAL)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_samples_key_ts ON samples (key, ts)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples (ts)")
    conn.execute("CREATE TABLE IF NOT EXISTS quality "
                 "(ts INTEGER, key TEXT, sent INTEGER, received INTEGER, avg_ms REAL, max_ms REAL, jitter REAL)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_quality_key_ts ON quality (key, ts)")
    conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)")
    conn.commit()
    return conn


def device_key(ip, entry):
    return entry.get("mac") or ip


def record_history(conn, ts, known, internet_up, internet_ms, save_devices):
    try:
        rows = [(ts, INTERNET_KEY, 1 if internet_up else 0, internet_ms)]
        if save_devices:
            by_key = {}
            for ip, d in known.items():
                online = 1 if d["online"] else 0
                ms = d["ms"] if d["online"] else None
                key = device_key(ip, d)
                if key not in by_key or online > by_key[key][0]:
                    by_key[key] = (online, ms)
            rows += [(ts, key, online, ms) for key, (online, ms) in by_key.items()]
        conn.executemany("INSERT INTO samples VALUES (?, ?, ?, ?)", rows)
        conn.commit()
        return ""
    except sqlite3.Error:
        return "Warning: history.db could not be written this scan."


def prune_history(conn, keep_days):
    cutoff = int(time.time()) - keep_days * 86400
    conn.execute("DELETE FROM samples WHERE ts < ?", (cutoff,))
    conn.execute("DELETE FROM quality WHERE ts < ?", (cutoff,))
    conn.commit()


def record_quality(conn, ts, quality):
    try:
        rows = [(ts, key, b["sent"], b["received"], b["avg"], b["max"], b["jitter"])
                for key, b in quality.items() if b]
        if rows:
            conn.executemany("INSERT INTO quality VALUES (?, ?, ?, ?, ?, ?, ?)", rows)
            conn.commit()
        return ""
    except sqlite3.Error:
        return "Warning: history.db could not be written this scan."


def quality_stats(conn, now_ts):
    day_start = now_ts - 86400
    hour_start = now_ts - 3600
    stats = {}

    def get(key):
        if key not in stats:
            stats[key] = {"loss_24h": None, "jitter_24h": None, "avg_ms": None, "max_ms": None,
                          "bursts_24h": 0, "verdict": "no recent data",
                          "buckets": [[None, None, None] for _ in range(BUCKET_COUNT)]}
        return stats[key]

    def loss_of(sent, received):
        return round(100.0 * (sent - received) / sent, 2) if sent else None

    for key, n, sent, received, jitter, max_ms, weighted, weight in conn.execute(
            "SELECT key, COUNT(*), SUM(sent), SUM(received), AVG(jitter), MAX(max_ms), "
            "SUM(avg_ms * received), SUM(CASE WHEN avg_ms IS NOT NULL THEN received END) "
            "FROM quality WHERE ts >= ? GROUP BY key", (day_start,)):
        entry = get(key)
        entry["bursts_24h"] = n
        entry["loss_24h"] = loss_of(sent, received)
        entry["jitter_24h"] = round(jitter, 1) if jitter is not None else None
        entry["max_ms"] = round(max_ms, 1) if max_ms is not None else None
        entry["avg_ms"] = round(weighted / weight, 1) if weight else None

    for key, sent, received, jitter in conn.execute(
            "SELECT key, SUM(sent), SUM(received), AVG(jitter) FROM quality WHERE ts >= ? GROUP BY key",
            (hour_start,)):
        get(key)["verdict"] = quality_verdict(loss_of(sent, received), jitter)

    for key, b, sent, received, jitter, avg_ms in conn.execute(
            "SELECT key, CAST((? - ts) / ? AS INTEGER) AS b, SUM(sent), SUM(received), AVG(jitter), AVG(avg_ms) "
            "FROM quality WHERE ts >= ? GROUP BY key, b", (now_ts, BUCKET_SECONDS, day_start)):
        index = BUCKET_COUNT - 1 - b
        if 0 <= index < BUCKET_COUNT:
            get(key)["buckets"][index] = [loss_of(sent, received),
                                          round(jitter, 1) if jitter is not None else None,
                                          round(avg_ms, 1) if avg_ms is not None else None]
    return stats


def history_since(conn):
    row = conn.execute("SELECT MIN(ts) FROM samples").fetchone()
    return row[0] if row else None


def history_stats(conn, now_ts):
    day_start = now_ts - 86400
    week_start = now_ts - 7 * 86400
    stats = {}

    def get(key):
        if key not in stats:
            stats[key] = {"uptime_24h": None, "uptime_7d": None, "avg_ms": None, "max_ms": None,
                          "samples_7d": 0, "buckets": [[None, None] for _ in range(BUCKET_COUNT)]}
        return stats[key]

    for key, n, ups in conn.execute(
            "SELECT key, COUNT(*), SUM(online) FROM samples WHERE ts >= ? GROUP BY key", (week_start,)):
        entry = get(key)
        entry["uptime_7d"] = round(100.0 * ups / n, 2)
        entry["samples_7d"] = n

    for key, n, ups, avg_ms, max_ms in conn.execute(
            "SELECT key, COUNT(*), SUM(online), AVG(ms), MAX(ms) FROM samples WHERE ts >= ? GROUP BY key",
            (day_start,)):
        entry = get(key)
        entry["uptime_24h"] = round(100.0 * ups / n, 2)
        entry["avg_ms"] = round(avg_ms, 1) if avg_ms is not None else None
        entry["max_ms"] = round(max_ms, 1) if max_ms is not None else None

    for key, b, n, ups, avg_ms in conn.execute(
            "SELECT key, CAST((? - ts) / ? AS INTEGER) AS b, COUNT(*), SUM(online), AVG(ms) "
            "FROM samples WHERE ts >= ? GROUP BY key, b", (now_ts, BUCKET_SECONDS, day_start)):
        index = BUCKET_COUNT - 1 - b
        if 0 <= index < BUCKET_COUNT:
            get(key)["buckets"][index] = [round(ups / n, 3),
                                          round(avg_ms, 1) if avg_ms is not None else None]
    return stats


def load_known():
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}
    known = {}
    for ip, d in data.items():
        if isinstance(d, dict):
            known[ip] = {"first_seen": d.get("first_seen", ""), "online": False, "misses": 0,
                         "ms": None, "name": d.get("name", ""), "mac": d.get("mac", ""),
                         "last_seen": d.get("last_seen", "")}
    return known


def run_report():
    if not os.path.exists(HISTORY_FILE):
        print("No history yet. Run the monitor for a while first, then try again.")
        return
    try:
        conn = open_history()
        now_ts = int(time.time())
        stats = history_stats(conn, now_ts)
        qstats = quality_stats(conn, now_ts)
        since_ts = history_since(conn)
        conn.close()
    except sqlite3.Error:
        print("Could not read history.db. Try again in a moment.")
        return

    known = load_known()
    nicknames, _ = load_nicknames()
    try:
        my_ip = get_my_network()[1]
    except OSError:
        my_ip = ""

    def pct(v):
        return "-" if v is None else f"{v:.1f}%"

    def ms(v):
        return "-" if v is None else f"{v:.0f} ms"

    print("UPTIME AND SPEED REPORT")
    if since_ts:
        print(f"Tracking since {datetime.fromtimestamp(since_ts):%Y-%m-%d %H:%M} "
              f"({format_duration(now_ts - since_ts)} of data)")
    print("Uptime only counts the time the monitor was running.")
    print("-" * 88)
    print(f"{'DEVICE':<22}{'IP ADDRESS':<16}{'UPTIME 24H':<12}{'UPTIME 7D':<12}"
          f"{'AVG PING':<11}{'MAX PING':<11}{'SCANS'}")
    print("-" * 88)

    rows = [("Internet", "-", stats.get(INTERNET_KEY))]
    seen = set()
    for ip in sorted(known, key=sort_key):
        d = known[ip]
        key = device_key(ip, d)
        if key in seen:
            continue
        seen.add(key)
        name = find_nickname(ip, d.get("mac"), nicknames, my_ip) or d.get("name") or "Unknown device"
        rows.append((name, ip, stats.get(key)))

    for name, ip, st in rows:
        if st is None:
            print(f"{name[:21]:<22}{ip:<16}no data yet")
        else:
            print(f"{name[:21]:<22}{ip:<16}{pct(st['uptime_24h']):<12}{pct(st['uptime_7d']):<12}"
                  f"{ms(st['avg_ms']):<11}{ms(st['max_ms']):<11}{st['samples_7d']}")
    print("-" * 88)

    print("\nCONNECTION QUALITY (last 24 hours)")
    print("Loss = pings that got no reply. Jitter = how much the delay bounces around. "
          "The rating looks at the last hour.")
    print("-" * 88)
    print(f"{'TO':<22}{'LOSS':<10}{'JITTER':<10}{'AVG PING':<11}{'MAX PING':<11}{'RATING NOW':<14}{'BURSTS'}")
    print("-" * 88)
    for label, key in (("Internet (8.8.8.8)", INTERNET_KEY), ("Router", ROUTER_KEY)):
        q = qstats.get(key)
        if q is None:
            print(f"{label:<22}no data yet")
            continue
        loss = "-" if q["loss_24h"] is None else f"{q['loss_24h']:.1f}%"
        jit = "-" if q["jitter_24h"] is None else f"{q['jitter_24h']:.1f} ms"
        print(f"{label:<22}{loss:<10}{jit:<10}{ms(q['avg_ms']):<11}{ms(q['max_ms']):<11}"
              f"{q['verdict']:<14}{q['bursts_24h']}")
    print("-" * 88)


def get_meta(conn, key):
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row[0] if row else None


def set_meta(conn, key, value):
    conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))
    conn.commit()


def latest_summary_slot(now, weekday, hour):
    slot = now.replace(hour=hour, minute=0, second=0, microsecond=0)
    slot -= timedelta(days=(slot.weekday() - weekday) % 7)
    if slot > now:
        slot -= timedelta(days=7)
    return slot


def iso_to_ts(text):
    try:
        return datetime.fromisoformat(text).timestamp()
    except (TypeError, ValueError):
        return 0


def quality_period(conn, since_ts):
    out = {}
    for key, sent, received, jitter, weighted, weight in conn.execute(
            "SELECT key, SUM(sent), SUM(received), AVG(jitter), SUM(avg_ms * received), "
            "SUM(CASE WHEN avg_ms IS NOT NULL THEN received END) FROM quality WHERE ts >= ? GROUP BY key",
            (since_ts,)):
        out[key] = {"loss": 100.0 * (sent - received) / sent if sent else None,
                    "jitter": jitter,
                    "avg_ms": weighted / weight if weight else None}
    return out


def build_summary(conn, known, nicknames, my_ip, now_ts):
    def pct(v):
        return "no data" if v is None else ("100%" if v >= 99.95 else f"{v:.1f}%")

    def name_or_ip(ip, entry):
        label = display_label(ip, entry, nicknames, my_ip)
        return ip if label == "Unknown device" else label

    week_start = now_ts - 7 * 86400
    stats = history_stats(conn, now_ts)
    quality = quality_period(conn, week_start)
    since_ts = history_since(conn)
    approved, _ = load_approved()

    first = datetime.fromtimestamp(week_start).strftime("%b %d")
    last = datetime.fromtimestamp(now_ts).strftime("%b %d")
    lines = [f"Weekly summary ({first} to {last})"]
    if since_ts and now_ts - since_ts < 6.5 * 86400:
        lines.append(f"Note: the monitor only has {format_duration(now_ts - since_ts)} of data so far.")
    lines.append("")

    net = stats.get(INTERNET_KEY)
    up_text = pct(net["uptime_7d"]) + " up" if net else "no data"
    outages = [o for o in read_csv_tail(OUTAGE_FILE, 1000) if iso_to_ts(o.get("start")) >= week_start]
    if outages:
        seconds = [int(o["seconds"]) for o in outages]
        lines.append(f"Internet: {up_text}, {len(outages)} outage(s), {format_duration(sum(seconds))} "
                     f"in total, longest {format_duration(max(seconds))}")
    else:
        lines.append(f"Internet: {up_text}, no outages")

    for key, name in ((INTERNET_KEY, "Internet"), (ROUTER_KEY, "Router")):
        q = quality.get(key)
        if q and q["loss"] is not None:
            jitter = "-" if q["jitter"] is None else f"{q['jitter']:.0f} ms"
            ping = "-" if q["avg_ms"] is None else f"{q['avg_ms']:.0f} ms"
            lines.append(f"{name} quality: {q['loss']:.1f}% of test pings lost, jitter {jitter}, average ping {ping}")

    lines += ["", "Devices (uptime this week):"]
    rows, seen = [], set()
    for ip in sorted(known, key=sort_key):
        d = known[ip]
        key = device_key(ip, d)
        st = stats.get(key)
        if key in seen or not st or not st["samples_7d"]:
            continue
        seen.add(key)
        rows.append((name_or_ip(ip, d), st["uptime_7d"]))
    for name, uptime in rows[:15]:
        lines.append(f"{name}: {pct(uptime)}")
    if len(rows) > 15:
        lines.append(f"...and {len(rows) - 15} more")
    if not rows:
        lines.append("No device data yet.")

    if since_ts and since_ts <= week_start + 86400:
        new = []
        for ip, d in known.items():
            try:
                first_seen = datetime.strptime(d.get("first_seen", ""), "%Y-%m-%d %H:%M:%S").timestamp()
            except ValueError:
                continue
            if first_seen >= week_start and ip != my_ip:
                note = " (not approved)" if is_stranger(ip, d, approved, my_ip) else ""
                label = name_or_ip(ip, d)
                new.append(f"{label}{note}" if label == ip else f"{label} ({ip}){note}")
        lines += ["", "New devices this week: " + (", ".join(new) if new else "none")]
        if approved is not None:
            alarms = sum(1 for r in read_csv_tail(LOG_FILE, 100000)
                         if r.get("event") == "stranger" and iso_to_ts(r.get("time")) >= week_start)
            lines.append(f"Stranger alarms: {alarms}")
    return "\n".join(lines)


def check_weekly_summary(conn, known, nicknames, my_ip, alerter, weekday, hour, now_ts):
    slot = latest_summary_slot(datetime.fromtimestamp(now_ts), weekday, hour).timestamp()
    last_sent = get_meta(conn, "last_summary")
    if last_sent is None:
        set_meta(conn, "last_summary", str(now_ts))
        return
    if float(last_sent) >= slot:
        return
    set_meta(conn, "last_summary", str(now_ts))
    alerter.queue(build_summary(conn, known, nicknames, my_ip, now_ts))


def run_summary_now():
    if not os.path.exists(HISTORY_FILE):
        print("No history yet. Run the monitor for a while first, then try again.")
        return
    try:
        conn = open_history()
        known = load_known()
        nicknames, _ = load_nicknames()
        try:
            my_ip = get_my_network()[1]
        except OSError:
            my_ip = ""
        text = build_summary(conn, known, nicknames, my_ip, int(time.time()))
        conn.close()
    except sqlite3.Error:
        print("Could not read history.db. Try again in a moment.")
        return

    print(text)
    print()
    settings, problem = load_alert_settings()
    if problem:
        print(problem)
    elif not configured_channels(settings):
        print("Phone alerts are not set up yet, so this was only shown here. See --test-alert.")
    else:
        problem = send_message(settings, text)
        print("Sent to your phone." if not problem else "It could not be sent: " + problem)


DASHBOARD = {"json": b"{}"}

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
  .badge { margin-left:8px; padding:1px 8px; border-radius:999px; font-size:11px; font-weight:600;
           background:#3d1f1f; color:var(--red); border:1px solid var(--red); vertical-align:1px; }
  .pill { display:inline-block; padding:1px 9px; border-radius:999px; font-size:12px; font-weight:600; margin-bottom:2px; }
  .pill.good { background:#12301a; color:var(--green); border:1px solid var(--green); }
  .pill.fair { background:#3a2f12; color:var(--amber); border:1px solid var(--amber); }
  .pill.poor { background:#3d1f1f; color:var(--red); border:1px solid var(--red); }
  .pill.none { background:transparent; color:var(--muted); border:1px solid var(--line); }
  .cap { color:var(--muted); font-size:11px; margin-top:3px; }
  .hnote { color:var(--muted); font-size:13px; margin:-4px 0 6px; }
  .hrow { display:grid; grid-template-columns:minmax(110px,0.8fr) minmax(220px,2fr) minmax(120px,1fr) 205px;
          gap:12px; align-items:center; padding:10px 0; border-bottom:1px solid var(--line); }
  .hrow:last-child { border-bottom:0; }
  .who-name { font-weight:600; }
  .who-sub { color:var(--muted); font-size:12px; }
  .strip { display:flex; gap:1px; height:20px; }
  .strip span { flex:1; border-radius:2px; }
  .b-good { background:var(--green); } .b-part { background:var(--amber); }
  .b-bad { background:var(--red); } .b-none { background:#2a323c; }
  .spark { width:100%; height:36px; display:block; }
  .spark path { stroke:#58a6ff; stroke-width:1.5; fill:none; vector-effect:non-scaling-stroke;
                stroke-linecap:round; stroke-linejoin:round; }
  .spark-empty { color:var(--muted); font-size:12px; }
  .hstats { font-size:13px; color:var(--muted); line-height:1.6; white-space:nowrap; }
  .legend { display:flex; gap:14px; flex-wrap:wrap; color:var(--muted); font-size:12px; margin-top:10px; }
  .legend i { display:inline-block; width:10px; height:10px; border-radius:2px; margin-right:5px; vertical-align:-1px; }
  @media (max-width:760px) { .hrow { grid-template-columns:1fr; gap:6px; } }
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
    <div class="card"><div class="label">Connection quality</div><div class="value small" id="stat-quality">-</div>
      <div class="note-text" id="stat-quality-note"></div></div>
    <div class="card"><div class="label">Stranger alarm</div><div class="value small" id="stat-stranger">-</div>
      <div class="note-text" id="stat-stranger-note"></div></div>
    <div class="card"><div class="label">Phone alerts</div><div class="value small" id="stat-alerts">-</div></div>
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

  <section class="panel">
    <h2>Connection quality (last 24 hours)</h2>
    <div class="hnote" id="quality-note">Collecting data...</div>
    <div id="quality"></div>
    <div class="legend">
      <span><i class="b-good"></i>1% lost or less</span>
      <span><i class="b-part"></i>1 to 3% lost</span>
      <span><i class="b-bad"></i>more than 3% lost</span>
      <span><i class="b-none"></i>no data</span>
      <span>Loss = test pings that got no reply. Jitter = how much the delay bounces around. Each block is 30 minutes.</span>
    </div>
  </section>

  <section class="panel">
    <h2>History (last 24 hours)</h2>
    <div class="hnote" id="history-note">Collecting data...</div>
    <div id="history"></div>
    <div class="legend">
      <span><i class="b-good"></i>online</span>
      <span><i class="b-part"></i>partly online</span>
      <span><i class="b-bad"></i>offline</span>
      <span><i class="b-none"></i>no data</span>
      <span>Each block is 30 minutes. The far right is now. Ping lines are scaled to each device's own highest value.</span>
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
    const nickCell = el("td", d.nickname ? d.nickname : "-", "nick");
    if (d.trust === "unknown") nickCell.appendChild(el("span", "not approved", "badge"));
    tr.appendChild(nickCell);
    tr.appendChild(cell(d.ip, "mono"));
    tr.appendChild(cell(d.ms !== null && d.ms !== undefined ? Math.round(d.ms) + " ms" : "", ""));
    tr.appendChild(cell(d.mac, "mono"));
    tr.appendChild(cell(d.name, ""));
    tr.appendChild(cell(timeOf(d.last_seen), ""));
    body.appendChild(tr);
  });
}

function eventText(e) {
  if (e.ip === "internet" || e.ip === "router") {
    const what = e.ip === "internet" ? "the internet" : "the router";
    if (e.event === "down") return "Internet went down (" + e.name + ")";
    if (e.event === "back") return "Internet is back (" + e.name + ")";
    if (e.event === "poor") return "Connection to " + what + " is poor (" + e.name + ")";
    if (e.event === "recovered") return "Connection to " + what + " is back to normal (" + e.name + ")";
  }
  const who = e.name && e.name !== e.ip ? e.name + " (" + e.ip + ")" : e.ip;
  if (e.event === "stranger") return "ALARM: " + who + " joined and is not approved";
  return who + " " + e.event;
}
function eventColor(e) {
  if (e.event === "joined" || e.event === "back" || e.event === "recovered") return "t-good";
  if (e.event === "down" || e.event === "stranger") return "t-bad";
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

function pct(v) {
  if (v === null || v === undefined) return "-";
  return v >= 99.95 ? "100%" : v.toFixed(1) + "%";
}
function msText(v) { return v === null || v === undefined ? "-" : Math.round(v) + " ms"; }

function strip(h, nowTs) {
  const wrap = el("div", null, "strip");
  for (let i = 0; i < 48; i++) {
    const b = h ? h.buckets[i] : [null, null];
    const block = el("span");
    let cls = "b-none", tip = "No data";
    if (b[0] !== null) {
      cls = b[0] >= 0.95 ? "b-good" : (b[0] > 0 ? "b-part" : "b-bad");
      tip = Math.round(b[0] * 100) + "% online";
      if (b[1] !== null) tip += ", average ping " + Math.round(b[1]) + " ms";
    }
    block.className = cls;
    const start = new Date((nowTs - (48 - i) * 1800) * 1000);
    block.title = start.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) + ": " + tip;
    wrap.appendChild(block);
  }
  return wrap;
}

function sparkline(h, emptyText) {
  const values = h ? h.buckets.map((b) => b[1]) : [];
  const numbers = values.filter((v) => v !== null && v !== undefined);
  if (numbers.length < 2) return el("div", emptyText || "Not enough ping data yet", "spark-empty");
  const top = Math.max(...numbers, 1);
  let d = "";
  let drawing = false;
  values.forEach((v, i) => {
    if (v === null || v === undefined) { drawing = false; return; }
    const x = (i / 47) * 240;
    const y = 34 - (v / top) * 30;
    d += (drawing ? " L" : " M") + x.toFixed(1) + " " + y.toFixed(1);
    if (!drawing) d += " l0.01 0";
    drawing = true;
  });
  const NS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", "0 0 240 36");
  svg.setAttribute("preserveAspectRatio", "none");
  svg.setAttribute("class", "spark");
  const path = document.createElementNS(NS, "path");
  path.setAttribute("d", d.trim());
  svg.appendChild(path);
  return svg;
}

function statsBlock(h) {
  const box = el("div", null, "hstats");
  if (!h) { box.appendChild(el("div", "No history yet")); return box; }
  box.appendChild(el("div", "Uptime  24h " + pct(h.uptime_24h) + "   7d " + pct(h.uptime_7d)));
  box.appendChild(el("div", "Ping  avg " + msText(h.avg_ms) + "   max " + msText(h.max_ms)));
  return box;
}

function historyRow(r, nowTs) {
  const row = el("div", null, "hrow");
  const who = el("div");
  who.appendChild(el("div", r.title, "who-name"));
  who.appendChild(el("div", r.sub, "who-sub"));
  row.appendChild(who);
  row.appendChild(strip(r.h, nowTs));
  row.appendChild(sparkline(r.h));
  row.appendChild(statsBlock(r.h));
  return row;
}

function renderHistory(s) {
  const box = $("history");
  clear(box);
  box.appendChild(historyRow({ title: "Internet", sub: "8.8.8.8 and 1.1.1.1", h: s.internet_history }, s.now_ts));
  s.devices.forEach((d) => {
    box.appendChild(historyRow({
      title: d.nickname || d.ip,
      sub: d.nickname ? d.ip : (d.name || ""),
      h: d.history,
    }, s.now_ts));
  });
  $("history-note").textContent = s.history_since
    ? "Tracking since " + shortDateTime(s.history_since) + ". Uptime only counts the time the monitor was running."
    : "Collecting data...";
}

function lossStrip(q, nowTs) {
  const wrap = el("div", null, "strip");
  for (let i = 0; i < 48; i++) {
    const b = q ? q.buckets[i] : [null, null, null];
    const block = el("span");
    let cls = "b-none", tip = "No data";
    if (b[0] !== null) {
      cls = b[0] <= 1 ? "b-good" : (b[0] <= 3 ? "b-part" : "b-bad");
      tip = b[0] + "% lost";
      if (b[1] !== null) tip += ", jitter " + Math.round(b[1]) + " ms";
      if (b[2] !== null) tip += ", average ping " + Math.round(b[2]) + " ms";
    }
    block.className = cls;
    const start = new Date((nowTs - (48 - i) * 1800) * 1000);
    block.title = start.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) + ": " + tip;
    wrap.appendChild(block);
  }
  return wrap;
}

function pillClass(verdict) {
  return verdict === "Good" ? "good" : verdict === "Fair" ? "fair" : verdict === "Poor" ? "poor" : "none";
}

function qualityRow(title, sub, q, nowTs) {
  const row = el("div", null, "hrow");
  const who = el("div");
  who.appendChild(el("div", title, "who-name"));
  who.appendChild(el("div", sub, "who-sub"));
  row.appendChild(who);

  const strip = el("div");
  strip.appendChild(lossStrip(q, nowTs));
  strip.appendChild(el("div", "Lost pings", "cap"));
  row.appendChild(strip);

  const spark = el("div");
  spark.appendChild(sparkline(q ? { buckets: q.buckets.map((b) => [null, b[1]]) } : null, "Not enough jitter data yet"));
  spark.appendChild(el("div", "Jitter", "cap"));
  row.appendChild(spark);

  const stats = el("div", null, "hstats");
  if (!q) {
    stats.appendChild(el("div", "No data yet"));
  } else {
    stats.appendChild(el("span", "Right now: " + q.verdict, "pill " + pillClass(q.verdict)));
    stats.appendChild(el("div", "Loss " + (q.loss_24h === null ? "-" : q.loss_24h + "%") +
      "   Jitter " + (q.jitter_24h === null ? "-" : q.jitter_24h + " ms")));
    stats.appendChild(el("div", "Ping  avg " + msText(q.avg_ms) + "   max " + msText(q.max_ms)));
  }
  row.appendChild(stats);
  return row;
}

function renderQuality(s) {
  const box = $("quality");
  clear(box);
  const quality = s.quality;
  const card = $("stat-quality");
  if (!quality.enabled) {
    card.textContent = "Off";
    card.className = "value small";
    $("stat-quality-note").textContent = "Use --quality-pings 10 to turn it on";
    box.appendChild(el("div", "Connection quality testing is switched off.", "spark-empty"));
    $("quality-note").textContent = "";
    return;
  }
  box.appendChild(qualityRow("Internet", "to 8.8.8.8", quality.internet, s.now_ts));
  box.appendChild(qualityRow("Router", "your WiFi and home network", quality.router, s.now_ts));
  $("quality-note").textContent = "Each scan sends a small burst of test pings to the internet and to your router. "
    + "If only the internet row looks bad, the problem is probably your provider. If the router row looks bad too, look at your WiFi.";

  const q = quality.internet;
  if (q) {
    card.textContent = q.verdict;
    card.className = "value small " + (q.verdict === "Good" ? "t-good" : q.verdict === "Fair" ? "t-warn" : q.verdict === "Poor" ? "t-bad" : "");
    $("stat-quality-note").textContent = "Internet, right now. Last 24h: " + (q.loss_24h === null ? "-" : q.loss_24h + "% lost")
      + ", jitter " + (q.jitter_24h === null ? "-" : q.jitter_24h + " ms");
  } else {
    card.textContent = "Measuring...";
    card.className = "value small";
    $("stat-quality-note").textContent = "";
  }
}

function render(s) {
  $("network").textContent = "Network " + s.network + "  |  router " + s.router + "  |  this PC " + s.my_ip;
  $("updated").textContent = "Updated " + s.updated + " (scan #" + s.scan + ", every " + s.interval + " s)";

  const online = s.devices.filter((d) => d.status !== "offline").length;
  $("stat-online").textContent = online;
  $("stat-total").textContent = "of " + s.devices.length + " devices ever seen";

  const net = $("stat-internet");
  if (s.internet.up) {
    net.textContent = "OK";
    net.className = "value t-good";
    const parts = [];
    if (s.internet.ms !== null) parts.push(Math.round(s.internet.ms) + " ms to the internet");
    if (s.internet_history && s.internet_history.uptime_7d !== null) parts.push(pct(s.internet_history.uptime_7d) + " up over 7 days");
    $("stat-internet-note").textContent = parts.join("  |  ");
  } else {
    net.textContent = "DOWN";
    net.className = "value t-bad";
    $("stat-internet-note").textContent = "since " + s.internet.since + ", likely cause: " + s.internet.cause;
  }

  const guard = s.stranger;
  const strangerValue = $("stat-stranger");
  if (!guard.active) {
    strangerValue.textContent = "Off";
    strangerValue.className = "value small";
    $("stat-stranger-note").textContent = "Run --approve in the terminal to turn it on";
  } else if (guard.unknown_online.length === 0) {
    strangerValue.textContent = "On, all clear";
    strangerValue.className = "value small t-good";
    $("stat-stranger-note").textContent = guard.approved_count + " approved devices";
  } else {
    strangerValue.textContent = guard.unknown_online.length + " not approved";
    strangerValue.className = "value small t-bad";
    $("stat-stranger-note").textContent = "See the devices table";
  }

  $("stat-alerts").textContent = s.alerts;

  const warnings = $("warnings");
  clear(warnings);
  if (guard.active && guard.unknown_online.length > 0) {
    const names = guard.unknown_online.map((u) => u.ip + (u.name ? " (" + u.name + ")" : "")).join(", ");
    warnings.appendChild(el("div", "Not approved and online now: " + names +
      ". If they are yours, run  python home_network_monitor.py --approve  in the terminal.", "banner err"));
  }
  s.warnings.forEach((text) => warnings.appendChild(el("div", text, "banner note")));

  renderDevices(s.devices);
  renderEvents(s.events);
  renderOutages(s.outages);
  renderQuality(s);
  renderHistory(s);
}

async function refresh() {
  try {
    const response = await fetch("/api/status", { cache: "no-store" });
    if (!response.ok) throw new Error("bad response");
    const snapshot = await response.json();
    $("lost").hidden = true;
    if (!snapshot.devices) return;
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
    try:
        with open(path, newline="", encoding="utf-8") as f:
            return list(csv.DictReader(f))[-count:]
    except OSError:
        return []


def publish_dashboard(known, nicknames, my_ip, network, router, round_number,
                      interval, internet, alerts_text, warnings, stats, since_ts, now_ts, approved, quality):
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
            "history": stats.get(device_key(ip, d)),
            "trust": trust_of(ip, d, approved, my_ip),
        })
    devices.sort(key=lambda x: (x["status"] == "offline", sort_key(x["ip"])))
    unknown_online = [{"ip": x["ip"], "name": x["nickname"] or x["name"], "mac": x["mac"]}
                      for x in devices if x["trust"] == "unknown" and x["status"] != "offline"]

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
        "now_ts": now_ts,
        "history_since": datetime.fromtimestamp(since_ts).strftime("%Y-%m-%d %H:%M:%S") if since_ts else None,
        "internet_history": stats.get(INTERNET_KEY),
        "quality": quality,
        "stranger": {"active": approved is not None,
                     "approved_count": len(approved) if approved is not None else 0,
                     "unknown_online": unknown_online},
    }
    DASHBOARD["json"] = json.dumps(snapshot).encode("utf-8")


class DashboardHandler(BaseHTTPRequestHandler):
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
        pass


class QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass


def start_dashboard(host, port):
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
    parser.add_argument("--approve", nargs="*", metavar="IP",
                        help="stranger alarm: go through devices one by one, or approve the given IPs")
    parser.add_argument("--unapprove", nargs="+", metavar="IP",
                        help="stranger alarm: take devices off the approved list")
    parser.add_argument("--summary-now", action="store_true",
                        help="show the weekly summary now (and send it to your phone), then stop")
    parser.add_argument("--summary-day", type=str.lower, choices=SUMMARY_DAYS, default="sunday",
                        help="day of the week for the weekly summary (default sunday)")
    parser.add_argument("--summary-hour", type=int, default=20,
                        help="hour of the day, 0 to 23, for the weekly summary (default 20)")
    parser.add_argument("--no-summary", action="store_true", help="turn the weekly summary off")
    parser.add_argument("--quality-pings", type=int, default=10,
                        help="pings per connection quality test each scan (default 10, 0 turns it off)")
    parser.add_argument("--keep-days", type=int, default=30,
                        help="days of history to keep (default 30)")
    parser.add_argument("--report", action="store_true",
                        help="print an uptime and speed report, then stop")
    parser.add_argument("--test-alert", action="store_true",
                        help="set up alerts.json and send a test message to your phone")
    args = parser.parse_args()

    if not 0 <= args.summary_hour <= 23:
        print("--summary-hour must be a number from 0 to 23.")
        return
    if args.report:
        run_report()
        return
    if args.summary_now:
        run_summary_now()
        return
    if args.approve is not None:
        run_approve(args.approve)
        return
    if args.unapprove:
        run_unapprove(args.unapprove)
        return
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

    known = load_known()
    alerter = Alerter()
    outage = None
    round_number = 0

    history = None
    history_problem = ""
    try:
        history = open_history()
        prune_history(history, args.keep_days)
    except sqlite3.Error:
        history = None
        history_problem = "Warning: history.db could not be opened, so uptime history is off."
    last_prune = time.time()
    alarm_times = {}
    burst_pool = ThreadPoolExecutor(max_workers=2)
    watcher = QualityWatcher()
    summary_day = SUMMARY_DAYS.index(args.summary_day)

    if args.no_dashboard or args.once:
        dashboard_text = "off"
    else:
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
            bursts = {}
            if args.quality_pings > 0:
                bursts = {INTERNET_KEY: burst_pool.submit(ping_burst, INTERNET_TARGETS[0], args.quality_pings),
                          ROUTER_KEY: burst_pool.submit(ping_burst, router, args.quality_pings)}
            results = sweep(network)
            quality = {key: future.result() for key, future in bursts.items()}
            arp_table = read_arp_table()
            nicknames, nickname_problem = load_nicknames()
            alerter.reload()
            approved, approved_problem = load_approved()

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

            elif internet_up and outage is not None:
                end = datetime.now()
                seconds = (end - outage["start"]).total_seconds()
                log_outage(outage["start"], end, seconds, outage["cause"])
                log_event("internet", "back", f"down for {format_duration(seconds)}")
                alerter.queue(f"Internet is back. It was down for {format_duration(seconds)} "
                              f"(since {outage['start'].strftime('%H:%M')}). "
                              f"Likely cause: {outage['cause']}.")
                outage = None

            trusted = internet_up or router_ok
            if trusted:
                update_devices(known, results, arp_table, nicknames, my_ip,
                               args.misses, alerter, baseline, approved, alarm_times)
            watcher.update(quality, internet_up, trusted, alerter)

            now_ts = int(time.time())
            if history is not None:
                history_problem = (record_history(history, now_ts, known, internet_up, internet_ms, trusted)
                                   or record_quality(history, now_ts, quality))
                if time.time() - last_prune > 86400:
                    try:
                        prune_history(history, args.keep_days)
                    except sqlite3.Error:
                        pass
                    last_prune = time.time()
                if not args.no_summary:
                    try:
                        check_weekly_summary(history, known, nicknames, my_ip, alerter,
                                             summary_day, args.summary_hour, now_ts)
                    except sqlite3.Error:
                        pass

            alerter.flush(internet_up)

            if outage:
                internet_text = (f"DOWN since {outage['start'].strftime('%H:%M:%S')}, "
                                 f"likely cause: {outage['cause']}")
            elif internet_ms is not None:
                internet_text = f"OK ({internet_ms:.0f} ms)"
            else:
                internet_text = "OK"

            warnings = [w for w in (nickname_problem, approved_problem, alerter.file_problem,
                                    alerter.send_problem, history_problem) if w]

            stats, qstats, since_ts = {}, {}, None
            if history is not None:
                try:
                    stats = history_stats(history, now_ts)
                    qstats = quality_stats(history, now_ts)
                    since_ts = history_since(history)
                except sqlite3.Error:
                    pass
            quality_snapshot = {"enabled": args.quality_pings > 0,
                                "internet": qstats.get(INTERNET_KEY), "router": qstats.get(ROUTER_KEY)}

            def burst_text(key, name):
                b = quality.get(key)
                if not b:
                    return f"{name}: not measured"
                jitter = "-" if b["jitter"] is None else f"{b['jitter']:.0f} ms"
                return f"{name}: {b['loss']:.0f}% lost, jitter {jitter}"
            if args.quality_pings > 0:
                quality_text = (burst_text(INTERNET_KEY, "internet") + "   |   "
                                + burst_text(ROUTER_KEY, "router") + "   (latest test)")
            else:
                quality_text = "off (use --quality-pings 10 to turn it on)"

            internet = {"up": internet_up, "ms": internet_ms,
                        "since": outage["start"].strftime("%H:%M:%S") if outage else None,
                        "cause": outage["cause"] if outage else None}
            publish_dashboard(known, nicknames, my_ip, network, router, round_number,
                              args.interval, internet, alerter.channels_text(), warnings,
                              stats, since_ts, now_ts, approved, quality_snapshot)

            show_table(known, my_ip, network, round_number, nicknames, warnings,
                       internet_text, router, alerter.channels_text(), dashboard_text, approved, quality_text)

            with open(STATE_FILE, "w", encoding="utf-8") as f:
                json.dump(known, f, indent=2)

            if args.once:
                break
            time.sleep(args.interval)

    except KeyboardInterrupt:
        print("\nStopped. Your logs are in", LOG_FILE, "and", OUTAGE_FILE)
    finally:
        burst_pool.shutdown(wait=False)
        if history is not None:
            history.close()


if __name__ == "__main__":
    main()