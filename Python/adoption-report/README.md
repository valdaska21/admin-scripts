# Bitwarden Adoption Report

A python script for Bitwarden admins that pulls data from the [Bitwarden Public API](https://bitwarden.com/help/public-api/) and produces structured CSV reports showing member adoption, vault engagement, and security posture across your organisation.

## Requirements

- Python 3.8+
- A Bitwarden **Teams** or **Enterprise** organisation
- An [organisation API key (Client ID + Client Secret)](https://bitwarden.com/help/public-api/#authentication)

## Setup

```bash
# 1. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate      # macOS / Linux
# .venv\Scripts\activate       # Windows

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Optional) Pre-configure credentials to skip the interactive wizard
cp .env.example .env
# Edit .env and fill in BW_CLIENT_ID and BW_CLIENT_SECRET
```

> The virtual environment keeps the script's dependencies isolated from your system Python.
> You only need to create it once. For subsequent runs, just activate it (`source .venv/bin/activate`) before running the script.

## Usage

### Interactive (recommended for first-time use)

```bash
python adoption_report.py
```

The script will walk you through:
1. Selecting your region — `bitwarden.com`, `bitwarden.eu`, or self-hosted — using arrow keys
2. Entering your Client ID and Client Secret (secret input is hidden)

### Non-interactive

Set credentials as environment variables (or in a `.env` file) and pass flags directly:

```bash
# US Cloud
python adoption_report.py --region us --days 90

# EU Cloud
python adoption_report.py --region eu --days 30

# Self-hosted
python adoption_report.py --region self-hosted --server-url https://bitwarden.example.com
```

### Options

| Flag | Default | Description |
|---|---|---|
| `--region` | *(interactive)* | `us`, `eu`, or `self-hosted` |
| `--server-url` | — | Base URL for self-hosted instances |
| `--days` | `90` | Activity window for event-based metrics |
| `--output` | `adoption_report` | Output folder prefix |

### Credentials

| Variable | Description |
|---|---|
| `BW_CLIENT_ID` | Organisation API client ID (`organization.xxxx-...`) |
| `BW_CLIENT_SECRET` | Organisation API client secret |

Find these in the **Admin Console → Settings → Organisation info → API key**.

Credentials entered interactively are held in memory only and are never written to disk.

## Output

Each run creates a dated folder containing two CSV files:

```
adoption_report_2026-04-09/
├── summary.csv    — organisation-level metrics (key/value)
└── members.csv    — one row per member with per-user metrics
```

Running the script again on the same day overwrites the folder. Running it on a different day creates a new one, giving you a dated history of snapshots.

## Metrics

### `summary.csv`

| Metric | Source |
|---|---|
| Total Seats / Confirmed / Pending / Revoked | Public API — members |
| Seat Utilisation % | Confirmed members ÷ licensed seats |
| Active Members (last N days) | Event logs — login events (type `1000`) |
| 2FA Adoption % | Public API — `twoFactorEnabled` per member |
| Autofill Adopters (last N days) | Event logs — autofill events (type `1114`) |
| SSO Linked Members | Public API — `ssoExternalId` populated |
| Password Reset Enrolled | Public API — `resetPasswordEnrolled` |
| Total Login / Autofill Events | Event logs — aggregated counts |
| Top Device Types | Event logs — `device` field across all events |
| Total Groups / Ungrouped Members | Public API — groups endpoint |
| Enabled Policies | Public API — policies endpoint |

### `members.csv`

| Column | Description |
|---|---|
| Email, Name | From member profile |
| Status | Invited / Accepted / Confirmed / Revoked |
| Role | Owner / Admin / User / Custom |
| 2FA Enabled | Yes/No |
| Password Reset Enrolled | Yes/No |
| SSO Linked | Yes/No |
| Active (Last N Days) | Yes if member logged in within the reporting window |
| Last Login Date | Timestamp of most recent login event |
| Last Activity Date | Timestamp of most recent event of any type |
| Login Count | Login events within the reporting window |
| Autofill Events | Autofill events within the reporting window |
| Password Views | Password reveal events |
| Item Views | Vault item view events |
| Items Created / Edited | Vault write activity |
| Failed Login Attempts | Failed password + failed 2FA events |
| Device Types Used | Unique client types seen in the reporting window |
| Group Count / Groups | Groups the member belongs to |

## Limitations

### Event log scope

Event logs only record activity on **organisation-owned items stored in collections**. Activity on items in a member's individual (personal) vault is not captured by Bitwarden event logs and is therefore absent from this report.

The following columns in `members.csv` are affected by this:

| Column | Caveat |
|---|---|
| Autofill Events | Org-owned items in collections only |
| Password Views | Org-owned items in collections only |
| Item Views | Org-owned items in collections only |
| Items Created | Org-owned items in collections only |
| Items Edited | Org-owned items in collections only |

Login Count, Failed Login Attempts, and Device Types Used are user-level events and are not subject to this limitation.

### Other limitations

- Client-side events are batched and sent every ~60 seconds, so very recent activity may not yet appear.
