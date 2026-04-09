#!/usr/bin/env python3
"""
Bitwarden Adoption Report
--------------------------
Generates adoption and usage metrics from the Bitwarden Public API
and exports them as structured CSV files.

Usage:
    python adoption_report.py                                    # interactive setup
    python adoption_report.py --region us|eu --days 90          # non-interactive
    python adoption_report.py --region self-hosted --server-url https://bw.example.com

Credentials (BW_CLIENT_ID / BW_CLIENT_SECRET) are read from environment variables
or a .env file. If either is missing the script launches an interactive wizard that
walks through region selection (bitwarden.com · bitwarden.eu · self-hosted) and
credential entry. Credentials entered interactively are stored in memory only and
are not written to disk.
"""

from __future__ import annotations

import argparse
import csv
import getpass
import os
import sys
import threading
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests
from dotenv import load_dotenv


# ---------------------------------------------------------------------------
# Terminal UI helpers
# ---------------------------------------------------------------------------

class _Colors:
    """ANSI color codes — all empty strings when stdout is not a TTY."""

    def __init__(self) -> None:
        _tty = sys.stdout.isatty()
        self.RESET  = "\033[0m"  if _tty else ""
        self.BOLD   = "\033[1m"  if _tty else ""
        self.DIM    = "\033[2m"  if _tty else ""
        self.RED    = "\033[31m" if _tty else ""
        self.GREEN  = "\033[32m" if _tty else ""
        self.CYAN   = "\033[36m" if _tty else ""


C = _Colors()

# ASCII-safe fallbacks for Windows consoles that lack Unicode/braille support
_WIN      = sys.platform == "win32"
_TICK     = "+" if _WIN else "✓"
_CROSS    = "x" if _WIN else "✗"
_BULLET   = ">" if _WIN else "▶"
_ELLIPSIS = "..." if _WIN else "…"
_HBAR     = "-" if _WIN else "─"


class Spinner:
    """Animated braille spinner for long-running steps.

    Usage::

        with Spinner("Fetching members") as sp:
            data = api_call()
            sp.done(f"{len(data)} members")   # optional detail string
    """

    _FRAMES = r"-\|/" if _WIN else "⠋⠙⠹⠸⠼⠴⠦⠧⠣⠏"

    def __init__(self, label: str) -> None:
        self.label = label
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._is_tty = sys.stdout.isatty()
        self._done = False

    def _spin(self) -> None:
        i = 0
        while not self._stop.is_set():
            frame = self._FRAMES[i % len(self._FRAMES)]
            sys.stdout.write(f"\r  {C.CYAN}{frame}{C.RESET}  {self.label}...")
            sys.stdout.flush()
            self._stop.wait(0.08)
            i += 1

    def __enter__(self) -> "Spinner":
        if self._is_tty:
            self._thread.start()
        else:
            sys.stdout.write(f"  {self.label}... ")
            sys.stdout.flush()
        return self

    def done(self, detail: str = "") -> None:
        """Finalise with a green check. Call inside the ``with`` block."""
        if self._done:
            return
        self._done = True
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join()
        detail_str = f"  {C.DIM}{detail}{C.RESET}" if detail else ""
        if self._is_tty:
            sys.stdout.write(
                f"\r\x1b[2K  {C.GREEN}{_TICK}{C.RESET}  {self.label}{detail_str}\n"
            )
        else:
            sys.stdout.write(f"{detail or 'done'}\n")
        sys.stdout.flush()

    def __exit__(self, exc_type: object, *_: object) -> None:
        if self._done:
            return
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join()
        if exc_type is None:
            if self._is_tty:
                sys.stdout.write(f"\r\x1b[2K  {C.GREEN}{_TICK}{C.RESET}  {self.label}\n")
                sys.stdout.flush()
            else:
                sys.stdout.write("done\n")
                sys.stdout.flush()
        else:
            if self._is_tty:
                sys.stdout.write(f"\r\x1b[2K  {C.RED}{_CROSS}{C.RESET}  {self.label}\n")
                sys.stdout.flush()


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Event type codes
EVENT_LOGIN = 1000
EVENT_CHANGED_PASSWORD = 1001
EVENT_FAILED_LOGIN = 1005
EVENT_FAILED_LOGIN_2FA = 1006
EVENT_VAULT_EXPORT_INDIVIDUAL = 1007
EVENT_ITEM_CREATED = 1100
EVENT_ITEM_EDITED = 1101
EVENT_ITEM_VIEWED = 1107
EVENT_PASSWORD_VIEWED = 1108
EVENT_AUTOFILL = 1114
EVENT_ORG_VAULT_EXPORT = 1602

# Device type enum → human-readable label
DEVICE_TYPES: dict[int, str] = {
    0: "Android",
    1: "iOS",
    2: "Chrome Extension",
    3: "Firefox Extension",
    4: "Opera Extension",
    5: "Edge Extension",
    6: "Windows Desktop",
    7: "macOS Desktop",
    8: "Linux Desktop",
    9: "Chrome Browser",
    10: "Firefox Browser",
    11: "Opera Browser",
    12: "Edge Browser",
    13: "IE Browser",
    14: "Unknown Browser",
    15: "Android Amazon",
    16: "UWP",
    17: "Safari Extension",
    18: "Vivaldi Extension",
    19: "Vivaldi Browser",
    20: "Safari Browser",
    21: "Mirror",
    25: "SDK",
    26: "Server",
}

MEMBER_STATUS: dict[int, str] = {
    -1: "Revoked",
    0: "Invited",
    1: "Accepted",
    2: "Confirmed",
}

MEMBER_TYPE: dict[int, str] = {
    0: "Owner",
    1: "Admin",
    2: "User",
    4: "Custom",
}

POLICY_TYPES: dict[int, str] = {
    0: "Two-Factor Authentication",
    1: "Master Password",
    2: "Password Generator",
    3: "Single Organisation",
    4: "Require SSO",
    5: "Organisation Data Ownership",
    6: "Disable Send",
    7: "Send Options",
    8: "Account Recovery Administration",
    9: "Maximum Vault Timeout",
    10: "Disable Personal Vault Export",
    11: "Activate Autofill",
    12: "Automatic App Log In",
    13: "Free Families Sponsorship",
    14: "Remove Unlock With PIN",
    15: "Restricted Item Types",
    16: "URI Match Defaults",
    17: "Autotype Default Setting",
    18: "Automatic User Confirmation",
    19: "Block Claimed Domain Account Creation",
}

REGION_URLS: dict[str, dict[str, str]] = {
    "us": {
        "api": "https://api.bitwarden.com",
        "identity": "https://identity.bitwarden.com",
    },
    "eu": {
        "api": "https://api.bitwarden.eu",
        "identity": "https://identity.bitwarden.eu",
    },
}


# ---------------------------------------------------------------------------
# Bitwarden API client
# ---------------------------------------------------------------------------

class BitwardenClient:
    def __init__(self, api_url: str, identity_url: str, client_id: str, client_secret: str) -> None:
        self.api_base = api_url.rstrip("/")
        self.identity_base = identity_url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self._token: Optional[str] = None

    def authenticate(self) -> None:
        """Obtain an OAuth2 Bearer token via the client credentials flow."""
        url = f"{self.identity_base}/connect/token"
        try:
            resp = requests.post(
                url,
                data={
                    "grant_type": "client_credentials",
                    "scope": "api.organization",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                },
                timeout=30,
            )
        except requests.RequestException as exc:
            print(f"{C.RED}ERROR:{C.RESET} Could not reach identity server — {exc}", file=sys.stderr)
            sys.exit(1)

        if resp.status_code != 200:
            try:
                msg = resp.json().get("error_description", resp.text)
            except Exception:
                msg = resp.text
            print(f"{C.RED}ERROR:{C.RESET} Authentication failed ({resp.status_code}) — {msg}", file=sys.stderr)
            sys.exit(1)

        token = resp.json().get("access_token")
        if not token:
            print(
                f"{C.RED}ERROR:{C.RESET} Authentication succeeded but no access_token in response.",
                file=sys.stderr,
            )
            sys.exit(1)
        self._token = token

    def _get(self, path: str, params: Optional[dict] = None) -> dict:
        """Make an authenticated GET request; exit with a clear message on failure."""
        headers = {"Authorization": f"Bearer {self._token}"}
        url = f"{self.api_base}{path}"
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=30)
        except requests.RequestException as exc:
            print(f"{C.RED}ERROR:{C.RESET} Request to {path} failed — {exc}", file=sys.stderr)
            sys.exit(1)

        if resp.status_code == 401:
            print(
                f"{C.RED}ERROR:{C.RESET} 401 Unauthorized. Your token may have expired or "
                "the client lacks organisation API access.",
                file=sys.stderr,
            )
            sys.exit(1)
        if not resp.ok:
            print(
                f"{C.RED}ERROR:{C.RESET} GET {path} returned {resp.status_code}: {resp.text}",
                file=sys.stderr,
            )
            sys.exit(1)

        return resp.json()

    def get_members(self) -> list[dict]:
        data = self._get("/public/members")
        return data.get("data", [])

    def get_groups(self) -> list[dict]:
        data = self._get("/public/groups")
        return data.get("data", [])

    def get_group_members(self, group_id: str) -> list[str]:
        """Return all org-member IDs belonging to a group, handling pagination.

        The endpoint may return either a plain JSON array or the standard
        {"object":"list","data":[...],"continuationToken":...} envelope.
        """
        member_ids: list[str] = []
        params: dict = {}
        while True:
            raw = self._get(f"/public/groups/{group_id}/member-ids", params=params)
            # Plain list response — no pagination possible
            if isinstance(raw, list):
                member_ids.extend(raw)
                break
            # Standard envelope response
            member_ids.extend(raw.get("data", []))
            token = raw.get("continuationToken")
            if not token:
                break
            params["continuationToken"] = token
        return member_ids

    def get_all_events(self, start: datetime, end: datetime) -> list[dict]:
        """
        Fetch all events between start and end, handling pagination.

        Always passes explicit start/end parameters — the API defaults to the last
        30 days when these are omitted, which would silently truncate a 90-day window.
        """
        events: list[dict] = []
        params: dict = {
            "start": start.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "end": end.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        }
        date_range = f"{start.strftime('%Y-%m-%d')} – {end.strftime('%Y-%m-%d')}"
        sys.stdout.write(
            f"  {C.CYAN}>{C.RESET}  Fetching events  {C.DIM}({date_range}){C.RESET}\n"
        )
        sys.stdout.flush()
        page = 1
        while True:
            sys.stdout.write(
                f"\r\x1b[2K    {C.DIM}page {page}...{C.RESET}"
            )
            sys.stdout.flush()
            data = self._get("/public/events", params=params)
            batch = data.get("data", [])
            events.extend(batch)
            token = data.get("continuationToken")
            if not token:
                break
            params = {
                "start": params["start"],
                "end": params["end"],
                "continuationToken": token,
            }
            page += 1
        sys.stdout.write(
            f"\r\x1b[2K  {C.GREEN}{_TICK}{C.RESET}  Fetching events  "
            f"{C.DIM}{len(events)} events{C.RESET}\n"
        )
        sys.stdout.flush()
        return events

    def get_policies(self) -> list[dict]:
        data = self._get("/public/policies")
        return data.get("data", [])

    def get_subscription(self) -> dict:
        return self._get("/public/organization/subscription")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_date(date_str: Optional[str]) -> Optional[datetime]:
    """Parse an ISO 8601 date string (with or without fractional seconds) to UTC datetime."""
    if not date_str:
        return None
    try:
        s = date_str.rstrip("Z")
        if "." in s:
            dt = datetime.strptime(s[:26], "%Y-%m-%dT%H:%M:%S.%f")
        else:
            dt = datetime.strptime(s, "%Y-%m-%dT%H:%M:%S")
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _pct(count: int, total: int) -> str:
    return f"{count / total * 100:.1f}%" if total else "N/A"


def _fmt_date(dt: Optional[datetime]) -> str:
    return dt.strftime("%Y-%m-%d %H:%M UTC") if dt else "N/A"


# ---------------------------------------------------------------------------
# Metrics computation
# ---------------------------------------------------------------------------

def compute_metrics(
    members: list[dict],
    groups: list[dict],
    group_members_map: dict[str, list[str]],
    events: list[dict],
    policies: list[dict],
    subscription: dict,
    days: int,
) -> tuple[dict, dict[str, dict]]:
    """
    Returns (org_summary, per_member_metrics).

    Key ID notes:
    - event.actingUserId  matches  member.userId  (cross-platform Bitwarden account UUID)
    - member.id is the org-scoped UUID used for group membership lookups
    - group_members_map values contain org-scoped member.id values
    """

    # Build org-scoped member ID → member dict
    member_by_org_id: dict[str, dict] = {m["id"]: m for m in members if "id" in m}

    # Build group name lookup
    group_name_by_id: dict[str, str] = {g["id"]: g.get("name", g["id"]) for g in groups}

    # member.id (org) → list of group names
    member_groups: dict[str, list[str]] = defaultdict(list)
    for group_id, org_member_ids in group_members_map.items():
        group_name = group_name_by_id.get(group_id, group_id)
        for org_id in org_member_ids:
            member_groups[org_id].append(group_name)

    grouped_org_ids: set[str] = {
        oid for ids in group_members_map.values() for oid in ids
    }

    # Build userId (Bitwarden account) → org member dict for event matching
    user_id_to_member: dict[str, dict] = {}
    for m in members:
        uid = m.get("userId")
        if uid:
            user_id_to_member[uid] = m

    # ---- Aggregate events by actingUserId (Bitwarden account UUID) ----
    login_counts: dict[str, int] = defaultdict(int)
    last_login: dict[str, datetime] = {}
    last_activity: dict[str, datetime] = {}
    autofill_counts: dict[str, int] = defaultdict(int)
    password_view_counts: dict[str, int] = defaultdict(int)
    item_view_counts: dict[str, int] = defaultdict(int)
    items_created_counts: dict[str, int] = defaultdict(int)
    items_edited_counts: dict[str, int] = defaultdict(int)
    failed_login_counts: dict[str, int] = defaultdict(int)
    device_sets: dict[str, set[str]] = defaultdict(set)
    active_user_ids: set[str] = set()          # Bitwarden account UUIDs with a login event
    device_totals: dict[str, int] = defaultdict(int)

    for event in events:
        uid: Optional[str] = event.get("actingUserId")
        if not uid:
            continue

        etype: int = event.get("type", -1)
        date: Optional[datetime] = _parse_date(event.get("date"))
        device_code: Optional[int] = event.get("device")
        device_label: str = (
            DEVICE_TYPES.get(device_code, f"Unknown ({device_code})")
            if device_code is not None
            else "Unknown"
        )

        if date:
            if uid not in last_activity or date > last_activity[uid]:
                last_activity[uid] = date

        if device_code is not None:
            device_sets[uid].add(device_label)
            device_totals[device_label] += 1

        if etype == EVENT_LOGIN:
            login_counts[uid] += 1
            active_user_ids.add(uid)
            if date and (uid not in last_login or date > last_login[uid]):
                last_login[uid] = date
        elif etype == EVENT_AUTOFILL:
            autofill_counts[uid] += 1
        elif etype == EVENT_PASSWORD_VIEWED:
            password_view_counts[uid] += 1
        elif etype == EVENT_ITEM_VIEWED:
            item_view_counts[uid] += 1
        elif etype == EVENT_ITEM_CREATED:
            items_created_counts[uid] += 1
        elif etype == EVENT_ITEM_EDITED:
            items_edited_counts[uid] += 1
        elif etype in (EVENT_FAILED_LOGIN, EVENT_FAILED_LOGIN_2FA):
            failed_login_counts[uid] += 1

    # ---- Build per-member metrics (keyed by org member ID) ----
    per_member: dict[str, dict] = {}
    for org_id, m in member_by_org_id.items():
        # userId links to event data; may be None for uninvited/not-yet-confirmed members
        uid = m.get("userId")

        is_active = uid in active_user_ids if uid else False
        g_names = sorted(member_groups.get(org_id, []))

        per_member[org_id] = {
            "email": m.get("email", ""),
            "name": m.get("name") or "",
            "status_label": MEMBER_STATUS.get(m.get("status", 2), str(m.get("status"))),
            "role_label": MEMBER_TYPE.get(m.get("type", 2), str(m.get("type"))),
            "two_fa_enabled": m.get("twoFactorEnabled", False),
            "reset_password_enrolled": m.get("resetPasswordEnrolled", False),
            "sso_linked": bool(m.get("ssoExternalId")),
            "is_active": is_active,
            "last_login_date": _fmt_date(last_login.get(uid) if uid else None),
            "last_activity_date": _fmt_date(last_activity.get(uid) if uid else None),
            "login_count": login_counts.get(uid, 0) if uid else 0,
            "autofill_events": autofill_counts.get(uid, 0) if uid else 0,
            "password_views": password_view_counts.get(uid, 0) if uid else 0,
            "item_views": item_view_counts.get(uid, 0) if uid else 0,
            "items_created": items_created_counts.get(uid, 0) if uid else 0,
            "items_edited": items_edited_counts.get(uid, 0) if uid else 0,
            "failed_logins": failed_login_counts.get(uid, 0) if uid else 0,
            "device_types": "; ".join(sorted(device_sets.get(uid, set()))) if uid else "",
            "group_count": len(g_names),
            "group_names": "; ".join(g_names),
        }

    # ---- Org-level summary ----
    total_members = len(members)
    confirmed = sum(1 for m in members if m.get("status") == 2)
    pending = sum(1 for m in members if m.get("status") in (0, 1))
    revoked = sum(1 for m in members if m.get("status") == -1)
    two_fa_count = sum(1 for m in members if m.get("twoFactorEnabled"))
    sso_linked_count = sum(1 for m in members if m.get("ssoExternalId"))
    reset_enrolled_count = sum(1 for m in members if m.get("resetPasswordEnrolled"))
    active_count = len(active_user_ids)

    # Autofill adopters: confirmed members with at least one autofill event in the window
    autofill_adopters = sum(
        1 for v in per_member.values()
        if v["autofill_events"] > 0 and v["status_label"] == "Confirmed"
    )

    pm_sub = (subscription.get("passwordManager") or {})
    total_seats: Optional[int] = pm_sub.get("seats")

    enabled_policies = [
        POLICY_TYPES.get(p.get("type", -1), f"Policy {p.get('type')}")
        for p in policies
        if p.get("enabled")
    ]

    top_devices = sorted(device_totals.items(), key=lambda x: x[1], reverse=True)[:5]
    top_devices_str = "; ".join(f"{name} ({count})" for name, count in top_devices) or "N/A"

    all_org_ids: set[str] = set(member_by_org_id.keys())
    ungrouped_count = len(all_org_ids - grouped_org_ids)

    org_summary = {
        "Report Date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "Reporting Window (days)": days,
        "Total Seats (Password Manager)": total_seats if total_seats is not None else "N/A",
        "Total Members": total_members,
        "Confirmed Members": confirmed,
        "Pending Invitations (Invited + Accepted)": pending,
        "Revoked Members": revoked,
        "Seat Utilisation": _pct(confirmed, total_seats) if total_seats else "N/A",
        f"Active Members (last {days} days)": active_count,
        f"Active Members % (of confirmed)": _pct(active_count, confirmed),
        "2FA Enabled": two_fa_count,
        "2FA Adoption % (of confirmed)": _pct(two_fa_count, confirmed),
        "SSO Linked Members": sso_linked_count,
        "Password Reset Enrolled": reset_enrolled_count,
        f"Autofill Adopters (last {days} days)": autofill_adopters,
        f"Autofill Adoption % (of confirmed)": _pct(autofill_adopters, confirmed),
        f"Total Login Events (last {days} days)": sum(login_counts.values()),
        f"Total Autofill Events (last {days} days)": sum(autofill_counts.values()),
        "Total Groups": len(groups),
        "Ungrouped Members": ungrouped_count,
        "Enabled Policies": "; ".join(enabled_policies) if enabled_policies else "None",
        "Top Device Types (by event volume)": top_devices_str,
    }

    return org_summary, per_member


# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------

def write_csv(
    output_prefix: str,
    org_summary: dict,
    per_member: dict[str, dict],
    days: int,
) -> tuple[str, str]:
    date_stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    folder = f"{output_prefix}_{date_stamp}"
    os.makedirs(folder, exist_ok=True)

    summary_path = os.path.join(folder, "summary.csv")
    members_path = os.path.join(folder, "members.csv")

    _EVENT_LOG_SCOPE_NOTE = (
        "Event log metrics reflect organisation-owned items stored in collections only. "
        "Activity on items in members' individual (personal) vaults is not recorded by "
        "Bitwarden event logs and is therefore not included in this report."
    )
    _EVENT_LOG_AFFECTED = (
        "Affected columns: Autofill Events, Password Views, Item Views, "
        "Items Created, Items Edited."
    )

    # Summary: two-column key/value table
    with open(summary_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Note", _EVENT_LOG_SCOPE_NOTE])
        writer.writerow(["", _EVENT_LOG_AFFECTED])
        writer.writerow([])
        writer.writerow(["Metric", "Value"])
        for k, v in org_summary.items():
            writer.writerow([k, v])

    # Members: one row per member
    active_col = f"Active (Last {days} Days)"
    fieldnames = [
        "Email",
        "Name",
        "Status",
        "Role",
        "2FA Enabled",
        "Password Reset Enrolled",
        "SSO Linked",
        active_col,
        "Last Login Date",
        "Last Activity Date",
        "Login Count",
        "Autofill Events",
        "Password Views",
        "Item Views",
        "Items Created",
        "Items Edited",
        "Failed Login Attempts",
        "Device Types Used",
        "Group Count",
        "Groups",
    ]

    def _yn(val: bool) -> str:
        return "Yes" if val else "No"

    with open(members_path, "w", newline="", encoding="utf-8") as f:
        # Write the scope note before column headers so it is visible when the
        # file is opened in a spreadsheet application.
        note_writer = csv.writer(f)
        note_writer.writerow(["Note", _EVENT_LOG_SCOPE_NOTE])
        note_writer.writerow(["", _EVENT_LOG_AFFECTED])
        note_writer.writerow([])

        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for metrics in per_member.values():
            writer.writerow({
                "Email": metrics["email"],
                "Name": metrics["name"],
                "Status": metrics["status_label"],
                "Role": metrics["role_label"],
                "2FA Enabled": _yn(metrics["two_fa_enabled"]),
                "Password Reset Enrolled": _yn(metrics["reset_password_enrolled"]),
                "SSO Linked": _yn(metrics["sso_linked"]),
                active_col: _yn(metrics["is_active"]),
                "Last Login Date": metrics["last_login_date"],
                "Last Activity Date": metrics["last_activity_date"],
                "Login Count": metrics["login_count"],
                "Autofill Events": metrics["autofill_events"],
                "Password Views": metrics["password_views"],
                "Item Views": metrics["item_views"],
                "Items Created": metrics["items_created"],
                "Items Edited": metrics["items_edited"],
                "Failed Login Attempts": metrics["failed_logins"],
                "Device Types Used": metrics["device_types"],
                "Group Count": metrics["group_count"],
                "Groups": metrics["group_names"],
            })

    return summary_path, members_path


# ---------------------------------------------------------------------------
# Interactive helpers
# ---------------------------------------------------------------------------

_DIVIDER = _HBAR * 60

_REGIONS = [
    ("bitwarden.com (US Cloud)", "https://api.bitwarden.com",      "https://identity.bitwarden.com"),
    ("bitwarden.eu (EU Cloud)", "https://api.bitwarden.eu",        "https://identity.bitwarden.eu"),
    ("Self-hosted",              None,                               None),
]


def _masked_input(prompt: str) -> str:
    """
    Read a line of input, echoing '*' for each character typed.
    Handles backspace and paste correctly. Falls back to getpass if not a TTY.

    Uses os.read/os.write directly on the file descriptor to avoid Python's
    BufferedReader caching bytes internally, which makes select-based drains
    unreliable (the OS buffer looks empty while bytes sit in Python's layer).
    """
    if not sys.stdin.isatty():
        return getpass.getpass(prompt)

    try:
        import termios
        import tty
    except ImportError:
        # Windows — termios/tty are Unix-only; getpass is cross-platform
        return getpass.getpass(prompt)

    fd  = sys.stdin.fileno()
    out = sys.stdout.fileno()
    old = termios.tcgetattr(fd)

    os.write(out, prompt.encode())

    chars: list[str] = []
    try:
        tty.setraw(fd)
        while True:
            ch = os.read(fd, 1)
            if ch in (b"\r", b"\n"):
                os.write(out, b"\r\n")
                # Drain any remaining bytes (e.g. the \n trailing a \r\n paste)
                # using non-blocking reads so we never hang.
                os.set_blocking(fd, False)
                try:
                    while True:
                        try:
                            os.read(fd, 64)
                        except BlockingIOError:
                            break
                finally:
                    os.set_blocking(fd, True)
                break
            elif ch in (b"\x7f", b"\x08"):  # backspace / delete
                if chars:
                    chars.pop()
                    os.write(out, b"\b \b")
            elif ch == b"\x03":             # Ctrl-C
                termios.tcsetattr(fd, termios.TCSADRAIN, old)
                raise KeyboardInterrupt
            elif ch >= b" ":               # printable character
                chars.append(ch.decode("utf-8", errors="replace"))
                os.write(out, b"*")
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)

    return "".join(chars)


def _arrow_select(options: list[str], default: int = 0) -> int:
    """
    Display an arrow-key navigable single-select menu.
    Returns the index of the chosen option.
    Falls back to a numbered prompt when stdin is not a TTY.
    """
    def _numbered_menu() -> int:
        for i, opt in enumerate(options):
            marker = f" {_BULLET}" if i == default else "  "
            print(f"  [{i + 1}]{marker} {opt}")
        while True:
            try:
                raw = input(f"  Enter number (1–{len(options)}): ").strip()
            except EOFError:
                print("\nERROR: No interactive input available.", file=sys.stderr)
                sys.exit(1)
            if raw.isdigit() and 1 <= int(raw) <= len(options):
                return int(raw) - 1
            print(f"  Please enter a number between 1 and {len(options)}.")

    if not sys.stdin.isatty():
        return _numbered_menu()

    try:
        import termios
        import tty
    except ImportError:
        # Windows — termios/tty are Unix-only; fall back to numbered menu
        return _numbered_menu()

    selected = default
    n = len(options)

    def _render() -> None:
        for i, opt in enumerate(options):
            indicator = "\033[1;36m▶\033[0m" if i == selected else " "
            # \x1b[2K erases the full line, \r moves to column 0 — prevents ghosting
            sys.stdout.write(f"\x1b[2K\r  {indicator} {opt}\n")
        sys.stdout.flush()

    _render()

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        while True:
            ch = sys.stdin.buffer.read(1)
            if ch in (b"\r", b"\n"):
                break
            if ch == b"\x1b":
                nxt = sys.stdin.buffer.read(1)
                if nxt == b"[":
                    arrow = sys.stdin.buffer.read(1)
                    if arrow == b"A":          # up
                        selected = (selected - 1) % n
                    elif arrow == b"B":        # down
                        selected = (selected + 1) % n
            elif ch == b"\x03":               # Ctrl-C
                termios.tcsetattr(fd, termios.TCSADRAIN, old)
                raise KeyboardInterrupt
            else:
                continue  # ignore other keys without redrawing
            # Move cursor back to first option line then redraw all options
            sys.stdout.write(f"\x1b[{n}A")
            _render()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)

    sys.stdout.write("\n")
    return selected


# ---------------------------------------------------------------------------
# Interactive credential + region setup
# ---------------------------------------------------------------------------


def setup_credentials() -> tuple[str, str, str, str]:
    """
    Walk the user through selecting a region and entering their API credentials.
    Credentials are stored in os.environ for this process only — nothing is
    written to disk.

    Returns (client_id, client_secret, api_url, identity_url).
    """
    print()
    print(f"{C.DIM}{_DIVIDER}{C.RESET}")
    print(f"  {C.BOLD}Bitwarden Adoption Report — Setup{C.RESET}")
    print(f"{C.DIM}{_DIVIDER}{C.RESET}")
    print()
    print("  Your Client ID and Client Secret are used to authenticate with")
    print("  the Bitwarden Public API.  They will be held in memory for this")
    print("  session only and will NOT be written to disk.")
    print()
    print(f"  {C.BOLD}How to find your credentials:{C.RESET}")
    print("    1. Open the Bitwarden web app → switch to the Admin Console")
    print("       (product switcher in the top-left corner)")
    print("    2. Go to  Settings → Organisation info")
    print('    3. Scroll down to the  "API key"  section')
    print("    4. Copy your  client_id  and  client_secret")
    print()
    print(f"  {C.DIM}Tip: set  BW_CLIENT_ID  and  BW_CLIENT_SECRET  as environment")
    print(f"  variables (or in a .env file) to skip this prompt next time.{C.RESET}")
    print()
    print(f"{C.DIM}{_DIVIDER}{C.RESET}")
    print()

    # ── Region selection ────────────────────────────────────────────────────
    print(f"  {C.BOLD}Select your Bitwarden region{C.RESET}  {C.DIM}(↑ ↓ to move, Enter to confirm){C.RESET}")
    print()
    region_labels = [r[0] for r in _REGIONS]
    choice = _arrow_select(region_labels, default=0)
    _, api_url, identity_url = _REGIONS[choice]
    print(f"\n  {C.GREEN}Selected:{C.RESET} {region_labels[choice]}")

    if api_url is None:
        # Self-hosted: ask for the instance URL
        print()
        print("  Enter your Bitwarden server URL")
        print("  (e.g. https://bitwarden.mycompany.com)")
        print()
        server_url = input("  Server URL: ").strip().rstrip("/")
        if not server_url:
            print("\nERROR: Server URL cannot be empty.", file=sys.stderr)
            sys.exit(1)
        if not server_url.lower().startswith("https://"):
            print("\nERROR: Server URL must use HTTPS (e.g. https://bw.example.com).", file=sys.stderr)
            sys.exit(1)
        api_url = f"{server_url}/api"
        identity_url = f"{server_url}/identity"
        print(f"  API URL      : {api_url}")
        print(f"  Identity URL : {identity_url}")

    # ── Credentials ─────────────────────────────────────────────────────────
    print()
    print(f"{C.DIM}{_DIVIDER}{C.RESET}")
    print()

    existing_id = os.environ.get("BW_CLIENT_ID", "")
    existing_secret = os.environ.get("BW_CLIENT_SECRET", "")

    if existing_id:
        print(f"  Client ID      (already set: {existing_id[:24]}...)")
        client_id = existing_id
    else:
        client_id = _masked_input("  Client ID      : ").strip()
        if not client_id:
            print("\nERROR: Client ID cannot be empty.", file=sys.stderr)
            sys.exit(1)

    if existing_secret:
        print("  Client secret  (already set — reusing)")
        client_secret = existing_secret
    else:
        client_secret = _masked_input("  Client secret  : ").strip()
        if not client_secret:
            print("\nERROR: Client secret cannot be empty.", file=sys.stderr)
            sys.exit(1)

    os.environ["BW_CLIENT_ID"] = client_id
    os.environ["BW_CLIENT_SECRET"] = client_secret

    print()
    print(f"{C.DIM}{_DIVIDER}{C.RESET}")
    print(f"  {C.GREEN}All set{C.RESET} — starting report...")
    print(f"{C.DIM}{_DIVIDER}{C.RESET}")
    print()

    return client_id, client_secret, api_url, identity_url


# ---------------------------------------------------------------------------
# Terminal summary table
# ---------------------------------------------------------------------------

_TABLE_WIDTH = 64  # visible characters per content line


def _print_summary_table(
    org_summary: dict,
    days: int,
    region_label: str,
    summary_path: str,
    members_path: str,
) -> None:
    """Render a clean sectioned summary table to stdout."""

    rule = f"  {C.DIM}{_HBAR * _TABLE_WIDTH}{C.RESET}"

    def section(title: str) -> None:
        print()
        print(f"  {C.BOLD}{C.CYAN}{title}{C.RESET}")
        print(f"  {C.DIM}{_HBAR * len(title)}{C.RESET}")

    def row(label: str, *values: str) -> None:
        """Dot-leader row.  Extra values (e.g. a percentage) are appended after the primary."""
        primary = str(values[0]) if values else ""
        suffix  = f"   {values[1]}" if len(values) > 1 and values[1] not in ("", "N/A") else ""
        content = f"    {label}"
        val_str = primary + suffix
        fill = _TABLE_WIDTH - len(content) - len(val_str) - 1
        dots = " " + C.DIM + ("." * max(2, fill)) + C.RESET + " "
        suffix_colored = (
            f"   {C.DIM}{values[1]}{C.RESET}"
            if len(values) > 1 and values[1] not in ("", "N/A")
            else ""
        )
        print(f"{content}{dots}{C.BOLD}{primary}{C.RESET}{suffix_colored}")

    def row_text(label: str, value: str, max_val: int = 30) -> None:
        """Row where the value may be long text — truncated cleanly."""
        if len(value) > max_val:
            value = value[: max_val - 1] + _ELLIPSIS
        row(label, value)

    g = org_summary  # shorthand

    # ── Header ──────────────────────────────────────────────────────────────
    print()
    print(rule)
    print(f"  {C.BOLD}Bitwarden Adoption Report{C.RESET}")
    print(f"  {C.DIM}{region_label}   ·   {g['Report Date']}   ·   last {days} days{C.RESET}")
    print(rule)

    # ── Seats ───────────────────────────────────────────────────────────────
    section("Seats")
    row("Total Seats",          str(g["Total Seats (Password Manager)"]))
    row("Confirmed Members",    str(g["Confirmed Members"]))
    row("Pending Invitations",  str(g["Pending Invitations (Invited + Accepted)"]))
    row("Revoked Members",      str(g["Revoked Members"]))
    row("Seat Utilisation",     str(g["Seat Utilisation"]))

    # ── Adoption ────────────────────────────────────────────────────────────
    section(f"Adoption  (last {days} days)")
    row("Active Members",
        str(g[f"Active Members (last {days} days)"]),
        g[f"Active Members % (of confirmed)"])
    row("2FA Enabled",
        str(g["2FA Enabled"]),
        g["2FA Adoption % (of confirmed)"])
    row("Autofill Adopters",
        str(g[f"Autofill Adopters (last {days} days)"]),
        g[f"Autofill Adoption % (of confirmed)"])
    row("SSO Linked Members",       str(g["SSO Linked Members"]))
    row("Password Reset Enrolled",  str(g["Password Reset Enrolled"]))

    # ── Activity ─────────────────────────────────────────────────────────────
    section(f"Activity  (last {days} days)")
    row("Login Events",    str(g[f"Total Login Events (last {days} days)"]))
    row("Autofill Events", str(g[f"Total Autofill Events (last {days} days)"]))
    row_text("Top Device Types", str(g["Top Device Types (by event volume)"]), max_val=32)

    # ── Groups & Policies ────────────────────────────────────────────────────
    section("Groups & Policies")
    row("Total Groups",       str(g["Total Groups"]))
    row("Ungrouped Members",  str(g["Ungrouped Members"]))
    row_text("Enabled Policies", str(g["Enabled Policies"]), max_val=32)

    # ── Footer ───────────────────────────────────────────────────────────────
    print()
    print(rule)
    print(f"  {C.GREEN}{_TICK}{C.RESET}  {C.DIM}{summary_path}{C.RESET}")
    print(f"  {C.GREEN}{_TICK}{C.RESET}  {C.DIM}{members_path}{C.RESET}")
    print(rule)
    print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    load_dotenv()

    parser = argparse.ArgumentParser(
        description="Generate a Bitwarden adoption report from the Public API.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Non-interactive usage (set env vars to skip the setup wizard):
  export BW_CLIENT_ID=organization.xxxx-...
  export BW_CLIENT_SECRET=your_secret

  python adoption_report.py --region us --days 90
  python adoption_report.py --region eu --days 30
  python adoption_report.py --region self-hosted --server-url https://bw.example.com
        """,
    )
    parser.add_argument(
        "--region",
        choices=["us", "eu", "self-hosted"],
        default=None,
        help="Bitwarden region: us, eu, or self-hosted (interactive if omitted)",
    )
    parser.add_argument(
        "--server-url",
        default=None,
        metavar="URL",
        help="Base URL for self-hosted instances (e.g. https://bw.example.com)",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=90,
        help="Activity window in days (default: 90)",
    )
    parser.add_argument(
        "--output",
        default="adoption_report",
        help="Output file prefix (default: adoption_report)",
    )
    args = parser.parse_args()

    if args.days < 1:
        parser.error(f"--days must be a positive integer (got: {args.days})")

    client_id = os.getenv("BW_CLIENT_ID")
    client_secret = os.getenv("BW_CLIENT_SECRET")

    if not client_id or not client_secret:
        # Interactive setup — also handles region selection
        client_id, client_secret, api_url, identity_url = setup_credentials()
    else:
        # Derive URLs from --region flag (or default to US)
        region = args.region or "us"
        if region == "self-hosted":
            if not args.server_url:
                parser.error("--server-url is required when --region is self-hosted")
            if not args.server_url.lower().startswith("https://"):
                parser.error("--server-url must use HTTPS (e.g. https://bw.example.com)")
            base = args.server_url.rstrip("/")
            api_url = f"{base}/api"
            identity_url = f"{base}/identity"
        else:
            api_url = REGION_URLS[region]["api"]
            identity_url = REGION_URLS[region]["identity"]

    # Derive a short region label for display
    if "bitwarden.eu" in api_url:
        region_label = "EU Cloud (bitwarden.eu)"
    elif "bitwarden.com" in api_url:
        region_label = "US Cloud (bitwarden.com)"
    else:
        region_label = f"Self-hosted ({api_url})"

    print()
    print(f"  {C.BOLD}Bitwarden Adoption Report{C.RESET}")
    print(f"  {C.DIM}Region  : {region_label}{C.RESET}")
    print(f"  {C.DIM}Window  : last {args.days} days{C.RESET}")
    print(f"  {C.DIM}Output  : {args.output}_<date>/{C.RESET}")
    print()

    client = BitwardenClient(api_url, identity_url, client_id, client_secret)

    with Spinner("Authenticating") as sp:
        client.authenticate()
        sp.done()

    with Spinner("Fetching members") as sp:
        members = client.get_members()
        sp.done(f"{len(members)} member{'s' if len(members) != 1 else ''}")

    with Spinner("Fetching groups") as sp:
        groups = client.get_groups()
        sp.done(f"{len(groups)} group{'s' if len(groups) != 1 else ''}")

    with Spinner("Fetching group memberships") as sp:
        group_members_map: dict[str, list[str]] = {}
        for g in groups:
            group_members_map[g["id"]] = client.get_group_members(g["id"])
        sp.done()

    with Spinner("Fetching subscription") as sp:
        subscription = client.get_subscription()
        sp.done()

    with Spinner("Fetching policies") as sp:
        policies = client.get_policies()
        sp.done()

    # Always compute explicit start/end — never rely on the API's 30-day default
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=args.days)
    # get_all_events manages its own inline progress output
    events = client.get_all_events(start, end)

    with Spinner("Computing metrics") as sp:
        org_summary, per_member = compute_metrics(
            members, groups, group_members_map, events, policies, subscription, args.days
        )
        sp.done()

    with Spinner("Writing CSV files") as sp:
        summary_path, members_path = write_csv(args.output, org_summary, per_member, args.days)
        sp.done()

    _print_summary_table(org_summary, args.days, region_label, summary_path, members_path)


if __name__ == "__main__":
    main()
