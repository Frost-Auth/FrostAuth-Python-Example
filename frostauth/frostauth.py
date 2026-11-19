"""FrostAuth SDK — Python port.

Mirrors sdk/frostauth.js wire behavior:
  - every response is Ed25519-verified over
    "timestamp\\nnonce\\nmethod\\npath\\nstatus\\nbody" (±60s skew, pinned key IDs),
  - init() pins the server's public key against the key baked into this build,
  - offline assertions verified locally when the network is gone,
  - DNS-hijack tripwire refuses loopback/private answers before any licence
    material is sent.

Requires: Python 3.11+, `cryptography` (see requirements.txt). No other deps.
"""

from __future__ import annotations

import base64
import hashlib
from http.client import HTTPException
import ipaddress
import json
import os
import platform as _platform
import random
import re
import socket
import subprocess
import threading
import time
import uuid
from urllib import request as _urlrequest, error as _urlerror
from urllib.parse import quote as _urlquote

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SDK_VERSION = "1.0.0"
DEFAULT_BASE_URL = "https://api.frostauth.cc"
MAX_SIGNATURE_SKEW_MS = 60_000
MAX_RETRY_AFTER_SECONDS = 10
ASSERTION_PREFIX = "frostauth:assertion:v1"

PUBLIC_KEYS = {
    "k2": "MCowBQYDK2VwAyEA7xdiHZqo4DmS4O1C8FavYq9Yqk5QbBkJiicb1MTTFzo",
}


class Codes:
    CONFIG = "CONFIG"
    NETWORK = "NETWORK"
    TIMEOUT = "TIMEOUT"
    NOT_INITIALIZED = "NOT_INITIALIZED"
    NOT_ACTIVATED = "NOT_ACTIVATED"
    SERVER_ERROR = "SERVER_ERROR"
    SIGNATURE = "SIGNATURE"
    RATE_LIMITED = "RATE_LIMITED"


class FrostAuthError(Exception):
    def __init__(self, message: str, *, code: str = Codes.SERVER_ERROR,
                 status: int = 0, retryable: bool = False, request_id: str | None = None,
                 retry_after: int | None = None):
        super().__init__(message)
        self.code = code
        self.status = status
        self.retryable = retryable
        self.request_id = request_id
        self.retry_after = retry_after

    @property
    def needs_activation(self) -> bool:
        return self.status == 404 and not self.retryable

    @property
    def terminal(self) -> bool:
        return (not self.retryable and not self.needs_activation
                and 400 <= self.status < 500)


def _spki_to_raw(b64: str) -> bytes:
    """base64url SPKI DER (44 bytes: 12-byte header + 32-byte Ed25519 key)."""
    s = (b64 or "").strip()
    pad = "=" * (-len(s) % 4)
    der = base64.urlsafe_b64decode(s + pad)
    if len(der) != 44:
        raise FrostAuthError("not a usable Ed25519 public key", code=Codes.CONFIG)
    return der[12:]


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode((s or "").strip() + "=" * (-(len(s or "")) % 4))


def _b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _claim_string(claims: dict) -> bytes:
    return "\n".join([
        ASSERTION_PREFIX, "1",
        str(claims.get("lic", "")), str(claims.get("pid", "")),
        str(claims.get("dev", "")), str(claims.get("hwid", "")),
        str(claims.get("status", "")), str(claims.get("tier", "")),
        str(claims.get("exp", "")), str(claims.get("iat", "")),
        str(claims.get("nbf", "")), str(claims.get("naf", "")),
    ]).encode("utf-8")


def _parse_ms(value) -> int | None:
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str) and value.strip():
        s = value.strip()
        try:
            from datetime import datetime, timezone
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return int(dt.timestamp() * 1000)
        except ValueError:
            return None
    return None


def verify_assertion(assertion: str, pinned: dict[str, str], *,
                     hwid: str | None = None, at: int | None = None) -> tuple[bool, str, dict | None]:
    """Verify a server-issued offline assertion. Returns (ok, reason, claims)."""
    if not pinned:
        return False, "no pinned public key", None
    at = at if at is not None else int(time.time() * 1000)

    parts = str(assertion or "").split(".")
    if len(parts) != 3:
        return False, "malformed", None
    payload, sig_b64, key_id = parts

    candidates: list[bytes] = []
    for kid, val in pinned.items():
        if key_id == "" or kid == key_id:
            candidates.append(_spki_to_raw(val))
    if not candidates:
        return False, f'signed with key "{key_id}", which this build does not trust', None

    try:
        claims = json.loads(_b64u_decode(payload).decode("utf-8"))
    except Exception:
        return False, "unreadable", None

    try:
        signature = _b64u_decode(sig_b64)
    except Exception:
        return False, "unreadable", claims

    material = _claim_string(claims)
    ok = False
    for raw in candidates:
        try:
            Ed25519PublicKey.from_public_bytes(raw).verify(signature, material)
            ok = True
            break
        except (InvalidSignature, ValueError):
            continue
    if not ok:
        return False, "signature does not verify", claims

    if hwid and claims.get("hwid") != hwid:
        return False, "issued for a different machine", claims

    nbf = _parse_ms(claims.get("nbf"))
    naf = _parse_ms(claims.get("naf"))
    if nbf is None or naf is None or naf <= nbf:
        return False, "offline window is missing or unreadable", claims
    if at < nbf:
        return False, "not yet valid", claims
    if at > naf:
        return False, "offline period has run out", claims
    if claims.get("exp"):
        exp = _parse_ms(claims.get("exp"))
        if exp is None or at > exp:
            return False, "licence expired", claims
    return True, "", claims


# ── machine identity ─────────────────────────────────────────────────────────

_machine_cache: str | None = None


def _run(cmd: list[str], timeout: float = 5.0) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return out.stdout if out.returncode == 0 else ""
    except Exception:
        return ""


def _raw_machine_id() -> str:
    global _machine_cache
    if _machine_cache:
        return _machine_cache
    system = _platform.system()
    if system == "Windows":
        out = _run(["reg", "query", r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid"])
        m = re.search(r"MachineGuid\s+REG_SZ\s+(\S+)", out)
        if m:
            _machine_cache = m.group(1)
            return _machine_cache
    elif system == "Darwin":
        out = _run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"])
        m = re.search(r'"IOPlatformUUID"\s*=\s*"([^"]+)"', out)
        if m:
            _machine_cache = m.group(1)
            return _machine_cache
    elif system == "Linux":
        for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            try:
                with open(path) as fh:
                    val = fh.read().strip()
                if val:
                    _machine_cache = val
                    return _machine_cache
            except OSError:
                continue
    _machine_cache = f"fallback:{socket.gethostname()}:{os.getenv('USERNAME') or os.getenv('USER') or 'unknown'}:{system}"
    return _machine_cache


def hardware_id(scope: str = "frostauth") -> str:
    """Scoped SHA-256 of the machine id — the raw id never leaves the device."""
    return hashlib.sha256(f"{scope}|{_raw_machine_id()}".encode()).hexdigest()


def _facet(v: str) -> str:
    return hashlib.sha256(str(v).encode()).hexdigest()[:32]


VM_MAC_PREFIXES = (
    "00:05:69", "00:0c:29", "00:1c:14", "00:50:56", "08:00:27", "0a:00:27",
    "00:15:5d", "00:1c:42", "52:54:00", "00:16:3e",
)
VM_NAME_PATTERN = re.compile(
    r"vmware|virtualbox|vbox|qemu|kvm|xen|hyper-?v|parallels|bhyve|virtual machine|innotek", re.I)


def hardware_profile() -> tuple[list[dict], bool]:
    """Advisory anti-clone facets. Only hashed values leave the device."""
    system = _platform.system()
    cpu = _platform.processor() or "unknown"
    if system == "Windows":
        out = _run(["reg", "query", r"HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0",
                    "/v", "ProcessorNameString"])
        m = re.search(r"ProcessorNameString\s+REG_SZ\s+(.+)", out)
        if m:
            cpu = m.group(1).strip()
    elif system == "Darwin":
        cpu = _run(["sysctl", "-n", "machdep.cpu.brand_string"]).strip() or cpu
    elif system == "Linux":
        try:
            with open("/proc/cpuinfo") as fh:
                for line in fh:
                    if line.startswith("model name"):
                        cpu = line.split(":", 1)[1].strip()
                        break
        except OSError:
            pass

    # One MAC via uuid (stdlib limitation; good enough for an advisory facet).
    mac_int = uuid.getnode()
    macs: list[str] = []
    all_virtual = True
    if (mac_int >> 40) & 0x03 != 0x03:  # not a locally-administered/random node
        mac = ":".join(f"{(mac_int >> i) & 0xFF:02x}" for i in range(40, -1, -8))
        macs.append(mac)
        if not mac[:8] in VM_MAC_PREFIXES:
            all_virtual = False
    else:
        all_virtual = False

    components = [
        {"n": "cpu", "v": _facet(f"{cpu}|{os.cpu_count() or 0}")},
        {"n": "ram", "v": _facet("unknown")},
        {"n": "arch", "v": _facet(_platform.machine())},
        {"n": "platform", "v": _facet(system)},
        {"n": "host", "v": _facet(socket.gethostname())},
    ]
    if macs:
        components.append({"n": "mac", "v": _facet(",".join(sorted(macs)))})

    virtual = (bool(macs) and all_virtual) or bool(VM_NAME_PATTERN.search(cpu))
    return components, virtual


# ── DNS-hijack tripwire ──────────────────────────────────────────────────────

def _assert_real_host(base_url: str) -> None:
    from urllib.parse import urlparse
    host = urlparse(base_url).hostname or ""
    bare = host.strip("[]")
    if (not bare or bare in ("localhost", "127.0.0.1", "::1")
            or _is_ip_literal(bare)):
        return
    try:
        infos = socket.getaddrinfo(bare, None)
    except socket.gaierror as e:
        raise FrostAuthError(
            f'cannot resolve the licence server host "{bare}" — refusing to continue',
            code=Codes.NETWORK) from e
    private = []
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr.split("%")[0])
        except ValueError:
            continue
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_unspecified:
            private.append(addr)
    if private:
        raise FrostAuthError(
            f'"{bare}" resolves to loopback or private space ({", ".join(sorted(set(private)))}) — '
            "this is what a hosts-file hijack or licence emulator looks like. "
            "Refusing to continue (allow_private_dns=True to override).",
            code=Codes.NETWORK)


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# ── client ───────────────────────────────────────────────────────────────────

class FrostAuth:
    def __init__(self, *, owner: str, product: str, version: str,
                 base_url: str = DEFAULT_BASE_URL, timeout: float = 10.0,
                 retries: int = 2, offline_grace_seconds: int = 900,
                 public_key: dict[str, str] | None = None,
                 allow_insecure: bool = False, allow_private_dns: bool = False,
                 hardware_id_override: str | None = None,
                 collect_hardware: bool = True, debug: bool = False):
        from urllib.parse import urlparse
        for name, v in (("owner", owner), ("product", product), ("version", version)):
            if not str(v or "").strip():
                raise FrostAuthError(f"{name} is required", code=Codes.CONFIG)
        self.owner, self.product, self.version = owner.strip(), product.strip(), version.strip()
        self.base_url = base_url or DEFAULT_BASE_URL
        self.timeout = timeout
        self.retries = max(0, retries)
        self.offline_grace_seconds = offline_grace_seconds
        self.allow_private_dns = allow_private_dns
        self.debug = debug

        u = urlparse(self.base_url)
        loopback = u.hostname in ("localhost", "127.0.0.1", "::1")
        if u.scheme != "https" and not loopback and not allow_insecure:
            raise FrostAuthError(
                "Refusing to send a licence key over plain http. Use https, or pass "
                "allow_insecure=True if you know what you are doing.", code=Codes.CONFIG)

        self._keys: dict[str, bytes] = {}
        for kid, val in (public_key or {}).items():
            if str(val or "").strip():
                self._keys[kid] = _spki_to_raw(val)

        self._hw_override = hardware_id_override
        self._machine_id: str | None = None
        self.collect_hardware = collect_hardware

        self.app: dict | None = None
        self.license: dict | None = None
        self.product_info: dict | None = None
        self.device: dict | None = None
        self.user: str | None = None
        self.account: dict | None = None
        self.subscriptions: list = []
        self.offline_until: str | None = None

        self._session: dict | None = None
        self._key: str | None = None
        self._assertion: str | None = None
        self._offline_since: float | None = None
        self.initialized = False
        self.activated = False
        self._closed = False

        self._lock = threading.RLock()
        self._hb_stop = threading.Event()
        self._hb_thread: threading.Thread | None = None

        # Event hooks — assign callables, e.g. app.on_invalid = lambda e: ...
        self.on_activated = None
        self.on_registered = None
        self.on_logged_in = None
        self.on_validated = None
        self.on_update_available = None
        self.on_offline = None
        self.on_invalid = None
        self.on_needs_activation = None

    # ── public API ───────────────────────────────────────────────────────

    @property
    def valid(self) -> bool:
        with self._lock:
            return self.activated and not self._closed

    def init(self) -> dict:
        _assert_real_host(self.base_url)
        path = f"/api/v1/settings/catalog/{_urlquote(self.owner, safe='')}/{_urlquote(self.product, safe='')}"
        body = self._request("GET", path, None, envelope=False)
        if not body or not body.get("success"):
            raise FrostAuthError(body.get("message") or "Application not found",
                                 code=body.get("error") or "APP_NOT_FOUND", status=404)
        key_id = str(body.get("key_id") or "")
        served = str(body.get("public_key") or "")
        pinned = PUBLIC_KEYS.get(key_id)
        if not key_id or not pinned or served != pinned:
            raise FrostAuthError("Server identity check failed — refusing to continue",
                                 code=Codes.SIGNATURE, status=401)
        with self._lock:
            self._keys = {key_id: _spki_to_raw(pinned)}
            self.app = {"name": body.get("app_name"), "ownerId": body.get("owner_id"),
                        "messages": body.get("errors") or {}}
            self.initialized = True
        return dict(self.app)

    def _require_init(self):
        if not self.initialized:
            raise FrostAuthError("Call init() before anything else", code=Codes.NOT_INITIALIZED)

    def _machine(self) -> str:
        with self._lock:
            if self._machine_id:
                return self._machine_id
            if self._hw_override:
                self._machine_id = str(self._hw_override)
                return self._machine_id
            scope = (self.app or {}).get("ownerId") or self.owner
            self._machine_id = hardware_id(scope)
            return self._machine_id

    def _hardware_extra(self) -> dict:
        if not self.collect_hardware:
            return {}
        try:
            components, virtual = hardware_profile()
            return {"components": components, "virtual": virtual}
        except Exception:
            return {}

    def activate(self, key: str, extra: dict | None = None) -> dict:
        self._require_init()
        key = str(key or "").strip()
        if not key:
            raise FrostAuthError("licence key is required", code=Codes.CONFIG)
        payload = {"key": key, "hwid": self._machine(), "os": _platform.system().lower(),
                   "appVersion": self.version, **self._hardware_extra()}
        extra = extra or {}
        if extra.get("hash"):
            payload["hash"] = extra["hash"]
        if extra.get("label"):
            payload["label"] = str(extra["label"])[:64]
        data = self._request("POST", "/api/v1/activate", payload)
        with self._lock:
            self._key = key
            self._adopt(data)
            self.activated = True
            self._offline_since = None
            snap = self.snapshot()
        if self.on_activated:
            self.on_activated(snap)
        return snap

    def register(self, key: str, username: str, password: str, extra: dict | None = None) -> dict:
        self._require_init()
        key = str(key or "").strip()
        if not key:
            raise FrostAuthError("licence key is required", code=Codes.CONFIG)
        payload = {"key": key, "username": username.strip(), "password": password,
                   "hwid": self._machine(), "os": _platform.system().lower(),
                   "appVersion": self.version, **self._hardware_extra()}
        extra = extra or {}
        if extra.get("hash"):
            payload["hash"] = extra["hash"]
        if extra.get("label"):
            payload["label"] = str(extra["label"])[:64]
        data = self._request("POST", "/api/v1/sdk/register", payload)
        with self._lock:
            self._key = key
            self._adopt(data)
            self.activated = True
            self._offline_since = None
            snap = self.snapshot()
        if self.on_registered:
            self.on_registered(snap)
        if self.on_activated:
            self.on_activated(snap)
        return snap

    def login(self, username: str, password: str, extra: dict | None = None) -> dict:
        self._require_init()
        payload = {"owner": self.owner, "product": self.product,
                   "username": username.strip(), "password": password,
                   "hwid": self._machine(), "os": _platform.system().lower(),
                   "appVersion": self.version, **self._hardware_extra()}
        extra = extra or {}
        if extra.get("twofa"):
            payload["twofa"] = str(extra["twofa"])
        if extra.get("hash"):
            payload["hash"] = extra["hash"]
        if extra.get("label"):
            payload["label"] = str(extra["label"])[:64]
        data = self._request("POST", "/api/v1/sdk/login", payload)
        with self._lock:
            self._adopt(data)
            self.activated = True
            self._offline_since = None
            snap = self.snapshot()
        if self.on_logged_in:
            self.on_logged_in(snap)
        if self.on_activated:
            self.on_activated(snap)
        return snap

    def upgrade(self, username: str, password: str, key: str) -> dict:
        self._require_init()
        return self._request("POST", "/api/v1/sdk/upgrade", {
            "owner": self.owner, "product": self.product,
            "username": username.strip(), "password": password,
            "key": str(key or "").strip()})

    def _authed(self, method: str, path: str, body=None) -> dict:
        with self._lock:
            token = (self._session or {}).get("token")
        if not token:
            raise FrostAuthError("This call needs a session — activate or sign in first",
                                 code=Codes.NOT_ACTIVATED)
        return self._request(method, path, body, token=token)

    def logout(self) -> dict:
        with self._lock:
            has_token = bool((self._session or {}).get("token"))
        try:
            if has_token:
                return self._authed("POST", "/api/v1/sdk/logout")
            return {"signedOut": True}
        finally:
            self.close()

    def session(self) -> dict:
        data = self._authed("GET", "/api/v1/sdk/session")
        with self._lock:
            self._adopt(data)
            return self.snapshot()

    def variable(self, key: str) -> str:
        data = self._authed("GET", f"/api/v1/sdk/vars/app/{_urlquote(key, safe='')}")
        return data.get("value")

    def list_vars(self) -> list:
        data = self._authed("GET", "/api/v1/sdk/vars/user")
        return data.get("variables") or []

    def get_var(self, key: str) -> str:
        data = self._authed("GET", f"/api/v1/sdk/vars/user/{_urlquote(key, safe='')}")
        return data.get("value")

    def set_var(self, key: str, value) -> dict:
        return self._authed("PUT", f"/api/v1/sdk/vars/user/{_urlquote(key, safe='')}",
                            {"value": str(value if value is not None else "")})

    def change_username(self, username: str, password: str) -> dict:
        data = self._authed("PATCH", "/api/v1/sdk/username",
                            {"username": username.strip(), "password": password})
        with self._lock:
            if self.account is not None:
                self.account["username"] = data.get("username")
            if data.get("username"):
                self.user = data["username"]
        return data

    def log(self, message: str) -> dict:
        return self._authed("POST", "/api/v1/sdk/log", {"message": str(message or "")[:256]})

    def ban(self, reason: str = "") -> dict:
        try:
            return self._authed("POST", "/api/v1/sdk/ban", {"reason": str(reason or "")[:200]})
        finally:
            self.stop_heartbeat()
            with self._lock:
                self.activated = False
                self._assertion = None
                self.offline_until = None

    def fetch_online(self) -> dict:
        return self._authed("GET", "/api/v1/sdk/online")

    def check_blacklist(self) -> dict:
        return self._authed("GET", "/api/v1/sdk/checkblacklist")

    def webhook(self, web_id: str, params: str = "", body: str = "", conttype: str = "") -> dict:
        web_id = str(web_id or "").strip()
        if not web_id:
            raise FrostAuthError("webhook id is required", code=Codes.CONFIG)
        payload = {}
        if params:
            payload["params"] = str(params)[:2048]
        if body:
            payload["body"] = str(body)[:8192]
        if conttype:
            payload["conttype"] = str(conttype)[:128]
        return self._authed("POST", f"/api/v1/sdk/webhook/{_urlquote(web_id, safe='')}", payload)

    def app_data(self) -> dict:
        return self._authed("GET", "/api/v1/sdk/app")

    def file(self, file_id: str) -> bytes:
        # File downloads are disabled server-side (route unmounted) —
        # mirrors the JS reference SDK, which throws.
        raise FrostAuthError("File downloads are disabled on this server")

    def validate(self) -> dict:
        self._require_init()
        with self._lock:
            has_cred = bool((self._session or {}).get("token") or self._key)
        if not has_cred:
            raise FrostAuthError("Activate before validating", code=Codes.NOT_ACTIVATED)
        try:
            data = self._send_validate()
        except FrostAuthError as err:
            if err.code in ("INVALID_TOKEN", "INVALID_SESSION") and self._key:
                with self._lock:
                    self._session = None
                data = self._send_validate()
            else:
                raise
        with self._lock:
            self._adopt(data)
            self.activated = True
            self._offline_since = None
            snap = self.snapshot()
        if self.on_validated:
            self.on_validated(snap)
        return snap

    def start_heartbeat(self, interval_seconds: int | None = None) -> "FrostAuth":
        with self._lock:
            has_cred = bool((self._session or {}).get("token") or self._key)
            if self._hb_thread and self._hb_thread.is_alive():
                return self
            self._closed = False
        if not has_cred:
            raise FrostAuthError(
                "Nothing to heartbeat with: activate with a licence key, or sign in on a plan that issues session tokens.", code=Codes.NOT_ACTIVATED)
        self._hb_stop.clear()

        def tick():
            while not self._hb_stop.is_set():
                if interval_seconds:
                    wait = max(1, interval_seconds)
                else:
                    base = 180
                    with self._lock:
                        if self._session and self._session.get("heartbeatSeconds"):
                            base = int(self._session["heartbeatSeconds"])
                    wait = max(15, base) + random.uniform(0, 5)
                if self._hb_stop.wait(wait):
                    return
                try:
                    self.validate()
                except FrostAuthError as err:
                    if err.needs_activation:
                        with self._lock:
                            self.activated = False
                        self.stop_heartbeat()
                        if self.on_needs_activation:
                            self.on_needs_activation(err)
                        return
                    if err.code == Codes.SIGNATURE or err.terminal:
                        with self._lock:
                            self.activated = False
                        self.stop_heartbeat()
                        if self.on_invalid:
                            self.on_invalid(err)
                        return
                    with self._lock:
                        if self._offline_since is None:
                            self._offline_since = time.time()
                        offline_for = int(time.time() - self._offline_since)
                        assertion = self._assertion
                    verified = False
                    if assertion:
                        ok, _, _ = verify_assertion(
                            assertion, {k: v for k, v in self._pinned_b64().items()},
                            hwid=self._machine())
                        verified = ok
                    if self.on_offline:
                        self.on_offline(err, offline_for, verified)
                    if not verified and (assertion is not None or offline_for >= self.offline_grace_seconds):
                        with self._lock:
                            self.activated = False
                        self.stop_heartbeat()
                        if self.on_invalid:
                            self.on_invalid(FrostAuthError(
                                f"Could not reach the licence server for {offline_for}s",
                                code=Codes.NETWORK))
                        return

        self._hb_thread = threading.Thread(target=tick, daemon=True)
        self._hb_thread.start()
        return self

    def stop_heartbeat(self):
        self._hb_stop.set()
        self._hb_thread = None

    def close(self):
        with self._lock:
            self._closed = True
        self.stop_heartbeat()
        with self._lock:
            self._key = None
            self._session = None
            self.activated = False
            self.account = None
            self.subscriptions = []
            self._assertion = None
            self.offline_until = None
            self._offline_since = None

    def check_offline(self, at: int | None = None) -> tuple[bool, str]:
        with self._lock:
            assertion, hwid = self._assertion, self._machine()
            pins = {k: v for k, v in self._pinned_b64().items()}
        if not assertion:
            return False, "no assertion issued yet"
        if not pins:
            return False, "no pinned publicKey to verify against"
        ok, reason, _ = verify_assertion(assertion, pins, hwid=hwid, at=at)
        return ok, reason

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "app": self.app, "license": self.license, "product": self.product_info,
                "device": self.device, "user": self.user, "account": self.account,
                "subscriptions": self.subscriptions,
                "valid": self.activated and not self._closed,
            }

    # ── internals ────────────────────────────────────────────────────────

    def _pinned_b64(self) -> dict[str, str]:
        out = {}
        for kid, raw in self._keys.items():
            out[kid] = _b64u_encode(b"\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00" + raw)
        return out

    def _adopt(self, data: dict):
        with self._lock:
            if isinstance(data.get("session"), dict) and data["session"].get("token"):
                self._session = data["session"]
            self.license = data.get("license") or self.license
            self.product_info = data.get("product") or self.product_info
            self.device = data.get("device") or self.device
            self.user = data.get("user") or self.user
            self.account = data.get("account") or self.account
            self.subscriptions = data.get("subscriptions") or self.subscriptions
            off = data.get("offline") or {}
            if off.get("assertion"):
                self._assertion = off["assertion"]
                self.offline_until = off.get("notAfter")
            prod = data.get("product") or {}
            if prod.get("updateAvailable"):
                latest = prod.get("latest") or prod.get("version")
                if self.on_update_available:
                    self.on_update_available(self.version, latest)

    def _send_validate(self) -> dict:
        hwid = self._machine()
        with self._lock:
            token = (self._session or {}).get("token")
            key = self._key
        if token:
            payload = {"token": token, "hwid": hwid, "appVersion": self.version,
                       "os": _platform.system().lower()}
        else:
            if not key:
                raise FrostAuthError("activate before validating", code=Codes.NOT_ACTIVATED)
            payload = {"key": key, "hwid": hwid, "appVersion": self.version,
                       "os": _platform.system().lower()}
        return self._request("POST", "/api/v1/validate", payload)

    def _verify_response(self, resp, raw: bytes, nonce: str, method: str, path: str):
        if not self._keys:
            return
        headers = resp.headers

        def reject(why):
            raise FrostAuthError(f"Refusing an unverified answer from the licence server: {why}",
                                 code=Codes.SIGNATURE, status=resp.status)

        sig = headers.get("x-frost-signature")
        ts = headers.get("x-frost-timestamp")
        if not sig or not ts:
            reject("it was not signed")
        if headers.get("x-frost-nonce") != nonce:
            reject("it answered a different request")
        try:
            ts_n = int(ts)
        except (TypeError, ValueError):
            reject("bad timestamp")
        if abs(time.time() * 1000 - ts_n) > MAX_SIGNATURE_SKEW_MS:
            reject("it was signed too long ago")
        key_id = headers.get("x-frost-key-id") or ""
        raws = [v for k, v in self._keys.items() if key_id == "" or k == key_id]
        if not raws:
            reject(f'it was signed with key "{key_id}", which this build does not trust')
        material = "\n".join([ts, nonce, method.upper(), path, str(resp.status),
                              raw.decode("utf-8", "surrogateescape")]).encode("utf-8")
        try:
            signature = _b64u_decode(sig)
        except Exception:
            reject("bad signature encoding")
        ok = False
        for r in raws:
            try:
                Ed25519PublicKey.from_public_bytes(r).verify(signature, material)
                ok = True
                break
            except (InvalidSignature, ValueError):
                continue
        if not ok:
            reject("the signature did not match")

    def _one_request(self, method: str, path: str, body, token: str | None):
        nonce = _b64u_encode(os.urandom(16))
        now_ms = str(int(time.time() * 1000))
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = _urlrequest.Request(self.base_url + path, data=data, method=method.upper())
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json")
        req.add_header("User-Agent", f"frostauth-sdk-python/{SDK_VERSION} ({_platform.system()})")
        req.add_header("X-Frost-Nonce", nonce)
        req.add_header("X-Frost-Timestamp", now_ms)
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            resp = _urlrequest.urlopen(req, timeout=self.timeout)
        except _urlerror.HTTPError as e:
            resp = e  # HTTPError behaves like a response with .status/.headers/.read
        except _urlerror.URLError as e:
            reason = getattr(e, "reason", None)
            timed_out = isinstance(reason, (socket.timeout, TimeoutError)) or "timed out" in str(reason).lower()
            raise FrostAuthError(
                f"Request timed out after {self.timeout}s" if timed_out
                else "Could not reach the licence server",
                code=Codes.TIMEOUT if timed_out else Codes.NETWORK, retryable=True) from e
        except TimeoutError as e:
            raise FrostAuthError(f"Request timed out after {self.timeout}s",
                                 code=Codes.TIMEOUT, retryable=True) from e

        except (ConnectionError, HTTPException) as e:
            raise FrostAuthError("Could not reach the licence server",
                                 code=Codes.NETWORK, retryable=True) from e

        with resp:
            try:
                raw = resp.read(8 << 20)
            except TimeoutError as e:
                raise FrostAuthError(f"Request timed out after {self.timeout}s",
                                     code=Codes.TIMEOUT, retryable=True) from e
            except (ConnectionError, HTTPException) as e:
                raise FrostAuthError("Could not read the licence server response",
                                     code=Codes.NETWORK, retryable=True) from e
            status = resp.status if hasattr(resp, "status") else resp.code
            sig = resp.headers.get("x-frost-signature")
            if status != 429 or sig:
                self._verify_response(resp, raw, nonce, method, path)
            return status, raw, resp.headers

    def _request(self, method: str, path: str, body=None, *, envelope: bool = True,
                 token: str | None = None) -> dict:
        last_err: FrostAuthError | None = None
        for attempt in range(self.retries + 1):
            if attempt > 0:
                time.sleep(random.uniform(0, min(0.3 * (2 ** attempt), 15)))
            try:
                status, raw, headers = self._one_request(method, path, body, token)
            except FrostAuthError as err:
                if err.code == Codes.SIGNATURE:
                    raise
                last_err = err
                continue

            text = raw.decode("utf-8", "replace")

            if status == 429 and not headers.get("x-frost-signature"):
                try:
                    wait = int(headers.get("retry-after") or 2)
                except ValueError:
                    wait = 2
                wait = wait if 0 < wait <= MAX_RETRY_AFTER_SECONDS else 2
                last_err = FrostAuthError("Rate limited by the licence server",
                                          code=Codes.RATE_LIMITED, status=429,
                                          retryable=True, retry_after=wait)
                if attempt < self.retries:
                    time.sleep(wait)
                    continue
                raise last_err

            try:
                payload = json.loads(text) if text else None
            except json.JSONDecodeError:
                payload = None

            if status >= 500:
                typed = (payload or {}).get("response", {}).get("errorCode")
                if isinstance(typed, str) and typed:
                    raise FrostAuthError(
                        (payload or {}).get("response", {}).get("message") or f"Request failed ({status})",
                        code=typed, status=status)
                last_err = FrostAuthError(
                    (payload or {}).get("response", {}).get("message") or "The licence server is having trouble",
                    code=Codes.SERVER_ERROR, status=status, retryable=True)
                continue

            if not envelope:
                return payload or {}

            resp_obj = (payload or {}).get("response") or {}
            if (payload or {}).get("error") or not (200 <= status < 300):
                code = resp_obj.get("errorCode") or (payload or {}).get("error") or Codes.SERVER_ERROR
                if isinstance(code, bool):
                    code = Codes.SERVER_ERROR
                raise FrostAuthError(resp_obj.get("message") or f"Request failed ({status})",
                                     code=code, status=status)

            return resp_obj.get("data") or {}

        raise last_err or FrostAuthError("Request failed", code=Codes.NETWORK, retryable=True)
