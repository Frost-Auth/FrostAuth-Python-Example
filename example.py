"""FrostAuth Python SDK — console example. Mirrors sdk/example.mjs output.

Fill owner/product from your dashboard; set version to the build you ship.
"""

import hashlib
import sys
import time
from datetime import datetime

from frostauth import FrostAuth, FrostAuthError

OWNER = "0809wkVP"
PRODUCT = "33abf48a-8e33-4df5-a4bd-d79195704d52"
VERSION = "1.0.2"


def fail(err: Exception):
    if isinstance(err, FrostAuthError):
        print(f"An error occurred: {err}")
    else:
        print("An error occurred:", err)
    sys.exit(1)


def loc(iso: str) -> str:
    """Locale-style timestamp, e.g. 9/16/2026, 6:08:02 PM.

    Built by hand so it works on both Windows and Unix strftime.
    """
    if not iso:
        return "unknown"
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone()
    except ValueError:
        return "unknown"
    hour12 = dt.hour % 12 or 12
    return (
        f"{dt.month}/{dt.day}/{dt.year}, {hour12}:{dt.minute:02d}:{dt.second:02d}"
        f" {'AM' if dt.hour < 12 else 'PM'}"
    )


def show_user(snap: dict):
    lic = snap.get("license") or {}
    account = snap.get("account") or {}
    device = snap.get("device") or {}
    product = snap.get("product") or {}

    def when(v):
        if not v:
            return "—"
        s = loc(str(v))
        return s if s != "unknown" else "—"

    who = snap.get("user") or account.get("username") or "unknown"
    tier = lic.get("tier") or "starter"
    state = lic.get("status") or "unknown"

    expiry = lic.get("expiresAt")
    if not expiry:
        for s in snap.get("subscriptions") or []:
            if isinstance(s, dict) and s.get("expiresAt"):
                expiry = s["expiresAt"]
                break

    days_left = None
    if expiry:
        try:
            edt = datetime.fromisoformat(str(expiry).replace("Z", "+00:00"))
            now = datetime.now(edt.tzinfo) if edt.tzinfo else datetime.now()
            diff = (edt - now).total_seconds()
            days_left = 0 if diff <= 0 else int((diff + 86399) // 86400)
        except ValueError:
            days_left = None

    prod_name = product.get("name") or "—"
    prod_ver = product.get("version")
    prod_line = prod_name + (f" v{prod_ver}" if prod_ver else "")

    used = lic.get("devicesUsed")
    used_s = "—" if used is None else str(int(used) if isinstance(used, float) and used.is_integer() else used)
    if lic.get("unlimitedDevices"):
        devices_line = f"{used_s} (unlimited)"
    elif lic.get("deviceLimit"):
        devices_line = f"{used_s} / {lic['deviceLimit']}"
    else:
        devices_line = used_s

    dev_id = device.get("id") or "—"

    print("")
    print(f"Signed in as {who}")
    print("----------------------------------------------")
    print(f"  Licence ..... {state} ({tier})")
    print(f"  IP Address .. {account.get('lastIp') or '—'}")
    print(f"  Product ..... {prod_line}")
    print(f"  Devices ..... {devices_line}")
    print(f"  Valid Until . {when(expiry) + (f' ({days_left}d left)' if days_left is not None else '') if expiry else 'never'}")
    print(f"  Device Id ... {dev_id}")
    print(f"  First Seen .. {when(account.get('createdAt'))}")
    print(f"  Last Seen ... {when(account.get('lastLoginAt'))}")
    print("----------------------------------------------")


def dashboard(app: FrostAuth):
    snap = app.snapshot()

    show_user(snap)

    print("")

    subs = snap.get("subscriptions") or []
    for i, sub in enumerate(subs):
        name = sub.get("tier") or sub.get("status")
        expiry = loc(sub["expiresAt"]) if sub.get("expiresAt") else "never"
        print(f"[{i + 1}/{len(subs)}] | Subscription: {name} - Expiry: {expiry}")

    created = (snap.get("account") or {}).get("createdAt")
    print(f"Created at: {loc(created) if created else 'unknown'}")
    last_login = (snap.get("account") or {}).get("lastLoginAt")
    print(f"Last Login: {loc(last_login) if last_login else 'unknown'}")
    first_expiry = next((s["expiresAt"] for s in subs if s.get("expiresAt")), None)
    print(f"Expires: {loc(first_expiry) if first_expiry else 'never'}")

    try:
        import json
        res = app.webhook("discord", "", json.dumps({"content": "Hello from FrostAuth"}))
        print(f"\nWebhook test: upstream {res.get('status')} (ok: {res.get('ok')})")
    except FrostAuthError as e:
        print(f"\nWebhook test failed: {e.code or ''} {e}")

    with open(__file__, "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    print("\nBuild hash (this file):")
    print(f"  {digest}")
    print("  Pass it as {\"hash\": digest} to activate/register/login when the product requires it.")

    print("\nClosing app in 10 seconds...")
    time.sleep(10)
    try:
        app.logout()
    except FrostAuthError:
        pass


def main():
    app = FrostAuth(owner=OWNER, product=PRODUCT, version=VERSION)
    try:
        app.init()
    except FrostAuthError as e:
        fail(e)

    print("[1] Login\n[2] Register\n[3] License\n[4] Upgrade")
    option = input("Select an option: ").strip()

    try:
        if option == "1":
            app.login(input("Username: "), input("Password: "))
            dashboard(app)
        elif option == "2":
            app.register(input("License: "), input("Username: "), input("Password: "))
            dashboard(app)
        elif option == "3":
            app.activate(input("License: "))
            dashboard(app)
        elif option == "4":
            username = input("Username: ")
            password = input("Password: ")
            license_key = input("License: ")
            app.upgrade(username, password, license_key)
            print("Upgraded. Sign in to use the new licence.")
            app.login(username, password)
            dashboard(app)
        else:
            print("Invalid option selected.")
    except FrostAuthError as e:
        fail(e)


if __name__ == "__main__":
    main()
