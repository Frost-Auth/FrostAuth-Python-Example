# FrostAuth-Python-Example 🌟

Python example for the [FrostAuth license key API](https://www.frostauth.cc/).

Import `FrostAuth` from the bundled `frostauth` package and start with `example.py`. The SDK uses `cryptography` to verify Ed25519 signatures.

## Bugs

Open an issue if you can reproduce the failure with the example. Include your FrostAuth SDK version, `python --version`, and the exact error. Remove license keys and tokens before posting.

## Security practices

- If you use VMProtect or Themida, put the protector's markers around the license checks.
- Run integrity checks during the session. End the session if a check detects tampering.
- Keep files you need to protect on the server. Clear temporary buffers when the app is done with them.
- Use the API to recheck licenses and enforce access to server resources there. A local `isValid` flag alone can't enforce access.

## Copyright License

Copyright (c) 2026 FrostAuth. All rights reserved.

This SDK is distributed under Elastic License 2.0. See [LICENSE](LICENSE).

## What is FrostAuth?

FrostAuth is a cloud licensing API with device-bound keys, app accounts, and a dashboard for managing licenses and tracking activations. SDKs are available for C++, C#, Go, Java, JavaScript, Python, and Rust. For product questions, join the [FrostAuth Discord](https://www.frostauth.cc/discord).

## Requirements

Python 3.11 or newer and the dependencies in `requirements.txt`.

## Build

Run these commands from the SDK directory after setting your product details in the example.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python example.py
```

On Windows PowerShell, activate the virtual environment with `./.venv/Scripts/Activate.ps1`.

## `FrostAuth` instance definition

Copy the owner ID and product ID from the FrostAuth dashboard into `example.py`. Set the version you plan to ship.

```python
from frostauth import FrostAuth

OWNER = "0809y7MP"                                  # dashboard → product → owner id
PRODUCT = "33abf48a-8e33-4df5-a4bd-d79195704d52"    # dashboard → product → product id
VERSION = "1.0.0"                                   # must match the version you ship

app = FrostAuth(owner=OWNER, product=PRODUCT, version=VERSION)
```

## Initialize application

Call `init()` first. It fetches the public product catalog and checks the returned key ID and Ed25519 public key against the SDK's pin. The SDK uses the pinned key to verify signed responses.

```python
app.init()
```

## Display application information

Fetch application information after activation or sign-in returns a session token.

```python
app_data = app.app_data()
print("App version:", (app_data.get("product") or {}).get("version"))
```

## Check session validation

After activation or sign-in, call `validate()` to check the license again. If the API rejects a stale session token, the SDK retries once with the stored license key when it has one.

```python
app.validate()
```

## Check blacklist status

Check the blacklist with an active session. The API also checks it during activation and sign-in.

```python
app.check_blacklist()
```

## Login with username/password

Supply the account credentials. If the account uses two-factor authentication, include its code.

```python
snap = app.login(username, password)
```

## Register with username/password/key

```python
snap = app.register(key, username, password)
```

## Upgrade user with key

Apply the key to the existing account. Sign in after the upgrade to open a session.

```python
app.upgrade(username, password, key)
print("Upgraded. Sign in to use the new licence.")
snap = app.login(username, password)
```

## Login with just license key

For a key-only product, activate with the license key. The API applies the product's device rules and issues a session token where supported.

```python
snap = app.activate(key)
```

For products that check builds, pass `app.activate(key, {"hash": digest, "label": "Office desktop"})`. The label is optional.

## User Data

Read the current user, account, device, and subscriptions from the snapshot.

```python
snap = app.snapshot()
print("Username:", snap.get("user"))
print("IP:", (snap.get("account") or {}).get("lastIp"))
print("Device Id:", (snap.get("device") or {}).get("id"))
for sub in snap.get("subscriptions", []):
    print("Subscription:", sub.get("tier") or sub.get("status"))
```

## Check subscription of user

Use the tier name you set in the dashboard. The example checks for `pro`.

```python
subs = snap.get("subscriptions", [])
if not any((s.get("tier") or "").lower() == "pro" for s in subs):
    print("This feature needs a Pro subscription.")
    raise SystemExit(1)
```

## Application variables

Edit shared variables in the dashboard. The API applies each variable's tier and version rules on read.

```python
print("MOTD:", app.variable("maintenance_message"))
```

## User Variables

Read or update values for the signed-in user. The API rejects writes to variables the operator marked read-only.

```python
print(app.list_vars())            # every variable on this user
print(app.get_var("theme"))       # one variable's value
app.set_var("theme", "dark")      # write it back
```

## Application Logs

Send an event to the operator's log. The product's logging settings determine where it appears.

```python
app.log("client started, integrity check passed")
```

## Ban the user

Use an active session to ban the current device and IP address. The call also ends the local session.

```python
app.ban("debugger detected")  # reason shows on next login + dashboard
```

## Server-side webhooks

Call a webhook by its configured ID. The API stores the destination and the client supplies the parameters and body.

```python
res = app.webhook("discord", "", '{"content":"Hello from FrostAuth"}')
print("upstream:", res.get("status"), "ok:", res.get("ok"))
```

## Heartbeat & offline

After activation or sign-in, start the heartbeat. `check_offline()` verifies the cached signed assertion, including its expiry. If the assertion has expired or fails verification during an outage, the next failed heartbeat clears the active state. An invalid API response signature also stops the heartbeat and clears the active state.

Set `offline_grace_seconds` to change the 15-minute fallback for sessions that received no assertion. Set it to `0` to disable the fallback. If the server closes the connection mid-request, the SDK reports a retryable network error and applies the heartbeat policy.

```python
app.on_offline = lambda err, secs, verified: print("offline:", secs, verified)
app.start_heartbeat()   # server cadence until stop/close
ok, reason = app.check_offline()
if not ok:
    print("offline:", reason)
app.stop_heartbeat()
app.close()
```

## Compatibility checks

On Linux, run `bash sdk/compatibility/run.sh python` from the Cerberus root. The suite tests activation, validation, signed errors, and offline heartbeat behavior against a local API fixture.

This SDK initialized successfully against the live FrostAuth API on November 18, 2026. A live activation and heartbeat require a disposable license.

## SDK layout

- `frostauth/frostauth.py` contains the SDK.
- `example.py` runs the interactive example.
