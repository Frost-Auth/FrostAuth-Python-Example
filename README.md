# FrostAuth-Python-Example 🌟

FrostAuth Python example SDK for https://www.frostauth.cc license key API auth.

This example ships the SDK source directly — `frostauth/frostauth.py`.
`from frostauth import FrostAuth`, mirror `example.py`, and you're integrated.
One dependency: `cryptography`.

## Bugs

If you're running this example with no significant changes and something's broken,
open an issue with your FrostAuth version, Python version, and the exact error text.

We do **NOT** provide support for wiring FrostAuth into your project. If the
install steps below don't make sense yet, learn some Python first
(docs.python.org/YouTube), then come back.

## Security practices

* Ship releases through a protector/packer (PyInstaller + VMProtect on the
bundle, or Nuitka compiled) and put license checks behind their markers — a
plain `.py` next to your exe defeats the point.
* Run frequent integrity checks so patched memory kills the session instead of
granting access.
* Never write a downloaded file to disk if you don't want the user to have it.
Execute in memory and wipe the buffer the moment you're done.
* Treat every client answer as advisory. The server re-checks the license on
each call — don't add a local `is_valid` boolean that bypasses it.

FrostAuth signs every response and pins the server key, but no API survives a
client that trusts itself. Obfuscation + integrity checks stop tampering; the
API stops key sharing.

## Copyright License

Copyright (c) 2026 FrostAuth. All rights reserved.

This SDK is distributed under Elastic License 2.0. See [LICENSE](LICENSE).

## What is FrostAuth?

FrostAuth is a cloud licensing platform that protects your software from piracy
and unauthorized access. Hardware-locked licenses, secure auth, real-time
analytics, and a dashboard your customers never see. Client SDKs for Python
(this repo), C++, C#, Go, Rust, Java, and JavaScript. Come ask questions on
Discord: https://www.frostauth.cc/discord

## Requirements

* Python 3.10+

## Install & run

```bash
cd FrostAuth-Python-Example
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt                      # just: cryptography
python example.py
```

Or install the package itself (`pyproject.toml` included):

```bash
pip install .
```

## `FrostAuth` instance definition

Open your FrostAuth dashboard, pick your product, and copy the three values
into [`example.py`](example.py):

```python
OWNER = "YOUR-OWNER-ID"      # dashboard → product → owner id
PRODUCT = "YOUR-PRODUCT-ID"  # dashboard → product → product id
VERSION = "1.0.0"            # must match the version you ship

app = FrostAuth(owner=OWNER, product=PRODUCT, version=VERSION)
```

## Initialize application

You must call this before anything else. It fetches the public catalog and
pins the server's signing key (TOFU) — every later response is Ed25519-checked
against it, so a MITM serving a fake key aborts here instead of later.

```python
app.init()
```

## Display application information

```python
app_data = app.app_data()
prod = (app_data or {}).get("product", {})
print("App Version:", prod.get("version"))
print("Customer panel:", "enabled" if prod else "unknown")
```

## Check session validation

Re-checks the license/session with the server. Falls back from a stale session
token to the stored license key once.

```python
app.validate()  # raises FrostAuthError when the session is dead — exit, don't continue
```

## Check blacklist status

Whether this device/IP/key is blacklisted. Optional: the server already
refuses blacklisted callers on login/register, so this is just an early exit
for clients that want to close before showing UI.

```python
app.check_blacklist()  # raises on block — exit
```

## Login with username/password

```python
snap = app.login(username, password)
```

Pass 2FA/build extras as `app.login(user, pw, {"twofa": "123456"})`.

## Register with username/password/key

```python
snap = app.register(key, username, password)
```

## Upgrade user with key

Attaches a license key to an existing app user (adds time). Unlike login and
register this opens **no session** — sign the user in after a successful
upgrade.

```python
app.upgrade(username, password, key)
print("Upgraded. Sign in to use the new licence.")
snap = app.login(username, password)
```

## Login with just license key

For key-only products. Binds the key to this machine and opens a session —
no username needed.

```python
snap = app.activate(key)
```

Extra build evidence: `app.activate(key, {"hash": digest, "label": "Alex's desktop"})`
when the product has hash checks on.

## User Data

Everything about the current session lives in the snapshot:

```python
snap = app.snapshot()
print("Username:", snap.get("user"))
print("IP:", (snap.get("account") or {}).get("lastIp"))
print("Device Id:", (snap.get("device") or {}).get("id"))
for sub in snap.get("subscriptions", []):
    print("Subscription:", sub.get("tier") or sub.get("status"))
```

## Check subscription of user

Gate features by tier. Compare against the tier name you configured on the
dashboard — exact match, case-insensitive on the server side.

```python
subs = snap.get("subscriptions", [])
if not any((s.get("tier") or "").lower() == "pro" for s in subs):
    print("This feature needs a Pro subscription.")
    raise SystemExit(1)
```

## Application variables

Server-side strings, global for all users (feature flags, MOTD, config).
Read-only from the client; edit them on the dashboard. Tier- and
version-gated server-side.

```python
print("MOTD:", app.variable("maintenance_message"))
```

## User Variables

Per-user key/value pairs. Read and write them unless the operator marked one
read-only (balances, ranks — server-writable only).

```python
print(app.list_vars())            # every variable on this user
print(app.get_var("theme"))       # one variable's value
app.set_var("theme", "dark")      # write it back
```

## Application Logs

Ship an event to the operator log. Good for anti-debug alerts and crash
breadcrumbs. If the operator set a Discord webhook, it lands there instead of
the dashboard (dashboard logs rotate after 30 days).

```python
app.log("client started, integrity check passed")
```

## Ban the user

Blacklists the HWID + IP. Call it when your integrity checks catch tampering.
Only works after login. Ends the local session either way.

```python
app.ban("debugger detected")  # reason shows on next login + dashboard
```

## Server-sided webhooks

Fire an operator-configured webhook by id. The destination URL lives on the
server — the client only supplies params/body, so secrets never ship in your
binary. Tier-gated like files/variables.

```python
res = app.webhook("discord", "", '{"content":"Hello from FrostAuth"}')
print("upstream:", res.get("status"), "ok:", res.get("ok"))
```

## Download file

> Currently disabled server-side (route unmounted). `file()` raises
> `File downloads are disabled on this server` until file storage ships. The
> snippet below is the integration pattern for when it lands.

```python
blob = app.file("loader")
open("loader.bin", "wb").write(blob)
```

## Changing username

Lets a signed-in user rename themselves (password re-checked server-side).

```python
res = app.change_username(new_name, password)
print("Renamed to", res.get("username"))
```

## Heartbeat & offline

`validate()` on a timer keeps the session fresh. The SDK caches a signed
offline assertion — when the network drops, `check_offline()` verifies it
locally so the app keeps working inside the grace window.

```python
app.on_offline = lambda err, secs, verified: print("offline:", secs, verified)
app.start_heartbeat()   # server cadence until stop/close
# ...
app.stop_heartbeat()
app.close()
```

## SDK layout

* `frostauth/frostauth.py` — the whole SDK (`from frostauth import FrostAuth`).
* `example.py` — the interactive demo this README walks through.
