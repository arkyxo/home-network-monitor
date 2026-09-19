# Home Network Monitor

A small Python tool that watches your home WiFi. It finds every device on the network, tracks when devices join and leave, texts your phone about it, logs internet outages, and shows everything on a live web dashboard.

It is one file and uses only Python's standard library, so there is nothing to install.

![Dashboard with sample data](dashboard.png)

*The dashboard, shown here with made-up sample devices.*

## Features

- **Device discovery.** Sweeps the whole local network (254 addresses) by pinging each one, in parallel, in a few seconds.
- **Nicknames.** Give devices names like "Mom's phone". Names are saved against the device's MAC address, so they survive IP address changes.
- **Phone alerts.** Sends a Telegram and/or Discord message when a device joins or leaves. Alerts from one scan are bundled into a single message, and a device must miss several scans in a row before it counts as "left", so a sleeping phone does not cause false alarms.
- **Internet outage log.** Pings public servers to check the internet. When it goes down, the monitor pings the router to guess whether the problem is inside the home or with the internet provider, and records how long the outage lasted.
- **Live dashboard.** A built-in web page (about 5 second refresh) with device status, recent activity, and outage history. It also works on a phone.
- **Local CSV and JSON logs** of everything it sees.

## Requirements

- Python 3.8 or newer
- Developed and used on Windows. It uses the standard `ping` and `arp` commands, so macOS and Linux should work too, but they are less tested.

## Quick start

```
python home_network_monitor.py
```

Then open <http://localhost:8080> in your browser. Stop the monitor with Ctrl+C.

## Options

| Option | What it does |
| --- | --- |
| `--interval 10` | Seconds between scans (default 30) |
| `--misses 3` | Scans a device must miss in a row before it counts as "left" (default 3) |
| `--network 192.168.1.0/24` | Set the network by hand if auto-detect guesses wrong |
| `--router 192.168.1.1` | Set the router address by hand if auto-detect guesses wrong |
| `--once` | Scan one time, then stop |
| `--name IP "Nickname"` | Give a device a nickname |
| `--test-alert` | Create `alerts.json` and send a test message |
| `--port 8081` | Use a different dashboard port |
| `--share` | Let phones on the same WiFi open the dashboard |
| `--no-dashboard` | Turn the dashboard off |

## Nicknames

Find a device's IP address in the table, then run:

```
python home_network_monitor.py --name 192.168.1.23 "Mom's phone"
```

Nicknames are stored in `nicknames.json`. You can also edit that file by hand while the monitor runs, and the change appears on the next scan.

## Phone alerts

1. Run `python home_network_monitor.py --test-alert`. This creates `alerts.json`.
2. Fill in either the Telegram details (a bot token from `@BotFather` and your chat ID) or a Discord webhook URL.
3. Run `--test-alert` again. A test message should arrive on your phone.

`alerts.json` contains secrets. It is listed in `.gitignore`, so it is never uploaded. Do not share it.

You cannot be alerted about an internet outage while the internet is down. The monitor logs the outage immediately and sends the message as soon as the connection returns, with how long it lasted and the likely cause.

## Files it creates

| File | Contents |
| --- | --- |
| `devices.json` | Latest snapshot of every device seen |
| `network_log.csv` | Diary of joined, left, and internet down/back events |
| `outage_log.csv` | One line per internet outage, with duration and likely cause |
| `nicknames.json` | Your device nicknames |
| `alerts.json` | Your alert settings (secret) |

All of these stay on your computer and are excluded from Git.

## Security notes

- The dashboard listens only on your own computer by default. `--share` opens it to everyone on your WiFi, with no password, so use it only on a network you trust.
- Only scan networks you own or have permission to scan.
- Device names come from the network, so the dashboard always shows them as plain text, never as HTML.

## Known limitations

- Assumes a standard home network where the router hands out addresses in a /24 range (255 addresses).
- Devices that ignore ping requests (some phones with the screen off) can appear offline for a while.
- Phones that use a private or random WiFi address may show a different MAC address if that setting changes.
- The monitor only sees devices while it is running, so it needs a computer that stays on.

## Ideas for next steps

- Alarm for devices that have not been marked as known
- Online dashboard backed by a cloud database, with a login
- Simple port check for your own devices