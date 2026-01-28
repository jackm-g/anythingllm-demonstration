#!/usr/bin/env python3
"""
Query ThreatFox for recent IOCs (Indicators of Compromise).

Uses the get_iocs API to fetch IOCs seen in the last 1 day.
Auth key must be set via THREATFOX_AUTH_KEY in a .env file.

API docs: https://threatfox.abuse.ch/api/#recent-iocs
"""

import json
import os
import sys

import requests
from dotenv import load_dotenv

THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
DEFAULT_DAYS = 1


def get_recent_iocs(days: int = DEFAULT_DAYS) -> dict:
    """
    Query ThreatFox for IOCs first_seen in the last `days` days.

    Args:
        days: Number of days to filter IOCs (1–7). Default 1.

    Returns:
        API response as dict with keys query_status and data.
    """
    load_dotenv()
    auth_key = os.getenv("THREATFOX_AUTH_KEY")
    if not auth_key:
        raise ValueError(
            "THREATFOX_AUTH_KEY not set. Add it to a .env file or set the env var."
        )

    headers = {"Auth-Key": auth_key}
    payload = {"query": "get_iocs", "days": days}

    resp = requests.post(THREATFOX_API_URL, headers=headers, json=payload, timeout=60)
    resp.raise_for_status()
    return resp.json()


def main() -> None:
    days = int(os.getenv("THREATFOX_DAYS", str(DEFAULT_DAYS)))
    try:
        result = get_recent_iocs(days=days)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)
    except requests.RequestException as e:
        print(f"Request failed: {e}", file=sys.stderr)
        sys.exit(1)

    status = result.get("query_status", "unknown")
    if status != "ok":
        print(f"API returned query_status: {status}", file=sys.stderr)
        if "data" in result:
            print(result["data"], file=sys.stderr)
        sys.exit(1)

    data = result.get("data", [])
    print(json.dumps({"query_status": status, "count": len(data), "data": data}, indent=2))


if __name__ == "__main__":
    main()
