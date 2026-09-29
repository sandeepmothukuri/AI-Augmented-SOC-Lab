#!/usr/bin/env python3
"""
MISP Feed Automation Script
============================
Automatically enables, configures, and syncs threat intelligence feeds in MISP.
Supports OSINT feeds (Abuse.ch, MISP project feeds, OTX, etc.) and custom feeds.

Usage:
    python misp-feed-sync.py --enable-defaults       # Enable all recommended OSINT feeds
    python misp-feed-sync.py --list-feeds            # List configured feeds and status
    python misp-feed-sync.py --sync-all              # Trigger sync for all enabled feeds
    python misp-feed-sync.py --add-feed <url>        # Add a custom feed
    python misp-feed-sync.py --sync-feed <feed_id>   # Sync a specific feed by ID

Environment Variables:
    MISP_URL         - MISP instance URL (default: https://localhost)
    MISP_API_KEY     - MISP automation API key
"""

import argparse
import json
import logging
import os
import ssl
import sys
import time
import urllib.error
import urllib.request

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

MISP_URL = os.getenv("MISP_URL", "https://localhost")
MISP_API_KEY = os.getenv("MISP_API_KEY", "")

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

# Curated list of OSINT feeds recommended for SOC labs
DEFAULT_FEEDS = [
    {
        "name": "MISP Project Community Blocklist",
        "url": "https://www.misp-project.org/feeds/misp-blocklist.json",
        "provider": "MISP Project",
        "input_source": "network",
        "source_format": "misp",
        "enabled": True,
        "caching_enabled": True,
        "lookup_visible": True,
        "tags": ["MISP", "blocklist", "network"],
    },
    {
        "name": "Abuse.ch URLhaus Feed",
        "url": "https://urlhaus-api.abuse.ch/v1/urls/recent/",
        "provider": "Abuse.ch",
        "input_source": "network",
        "source_format": "misp",
        "enabled": True,
        "caching_enabled": True,
        "lookup_visible": True,
        "tags": ["URLhaus", "malware-url", "Abuse.ch"],
    },
    {
        "name": "Abuse.ch Feodo Tracker C2",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json",
        "provider": "Abuse.ch",
        "input_source": "network",
        "source_format": "misp",
        "enabled": True,
        "caching_enabled": True,
        "lookup_visible": True,
        "tags": ["C2", "botnet", "Feodo", "Abuse.ch"],
    },
    {
        "name": "Abuse.ch MalwareBazaar",
        "url": "https://mb-api.abuse.ch/api/v1/?query=get_recent&selector=100",
        "provider": "Abuse.ch",
        "input_source": "network",
        "source_format": "misp",
        "enabled": True,
        "caching_enabled": True,
        "lookup_visible": True,
        "tags": ["malware", "hash", "MalwareBazaar"],
    },
    {
        "name": "ESET Malware IOCs",
        "url": "https://www.misp-project.org/feeds/eset-malware.json",
        "provider": "ESET",
        "input_source": "network",
        "source_format": "misp",
        "enabled": True,
        "caching_enabled": True,
        "lookup_visible": True,
        "tags": ["malware", "ESET"],
    },
    {
        "name": "Emerging Threats Open Ruleset (IPs)",
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "provider": "Emerging Threats",
        "input_source": "network",
        "source_format": "text",
        "enabled": True,
        "caching_enabled": True,
        "lookup_visible": True,
        "tags": ["ET", "compromised-ip", "network"],
    },
    {
        "name": "CIRCL MISP Feed",
        "url": "https://www.circl.lu/doc/misp/feed-osint/",
        "provider": "CIRCL",
        "input_source": "network",
        "source_format": "misp",
        "enabled": True,
        "caching_enabled": True,
        "lookup_visible": True,
        "tags": ["CIRCL", "OSINT"],
    },
    {
        "name": "AlienVault OTX Pulses (via MISP)",
        "url": "https://otx.alienvault.com/api/v1/pulses/subscribed",
        "provider": "AlienVault OTX",
        "input_source": "network",
        "source_format": "misp",
        "enabled": False,  # Requires OTX API key configured in MISP settings
        "caching_enabled": True,
        "lookup_visible": True,
        "tags": ["OTX", "AlienVault", "threat-intel"],
    },
]


def _api_request(method: str, path: str, payload: dict | None = None) -> dict:
    """Generic MISP API request."""
    if not MISP_API_KEY:
        logger.error("MISP_API_KEY environment variable not set")
        sys.exit(1)

    url = f"{MISP_URL}{path}"
    body = json.dumps(payload).encode() if payload else None
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Authorization": MISP_API_KEY,
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        method=method,
    )
    try:
        with urllib.request.urlopen(req, context=SSL_CTX, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode()
        logger.error("MISP API error %s on %s %s: %s", exc.code, method, path, error_body)
        sys.exit(1)
    except Exception as exc:
        logger.error("Cannot reach MISP at %s: %s", MISP_URL, exc)
        sys.exit(1)


def list_feeds() -> None:
    """List all configured feeds and their status."""
    response = _api_request("GET", "/feeds/index")
    feeds = response if isinstance(response, list) else response.get("Feed", [])

    if not feeds:
        logger.info("No feeds configured.")
        return

    print(f"\n{'ID':<8}{'Name':<45}{'Provider':<22}{'Enabled':<10}{'Cached':<10}{'Format'}")
    print("-" * 105)
    for feed in feeds:
        f = feed.get("Feed", feed)
        feed_id = f.get("id", "N/A")
        name = f.get("name", "N/A")[:43]
        provider = f.get("provider", "N/A")[:20]
        enabled = "[YES]" if f.get("enabled") else "[NO]"
        cached = "[YES]" if f.get("caching_enabled") else "[NO]"
        fmt = f.get("source_format", "N/A")
        print(f"{feed_id:<8}{name:<45}{provider:<22}{enabled:<10}{cached:<10}{fmt}")

    print(f"\nTotal: {len(feeds)} feed(s)")


def enable_defaults() -> None:
    """Enable the curated list of default OSINT feeds."""
    logger.info("Configuring %d default OSINT feeds...", len(DEFAULT_FEEDS))
    success = 0
    skipped = 0

    for feed in DEFAULT_FEEDS:
        try:
            response = _api_request("POST", "/feeds/add", {"Feed": feed})
            feed_id = response.get("Feed", {}).get("id") or response.get("id", "?")
            status = "enabled" if feed["enabled"] else "added (disabled - needs API key)"
            logger.info("[%s] %s - %s", feed_id, feed["name"], status)
            success += 1
            time.sleep(0.5)  # Rate limit: avoid hammering the API
        except SystemExit:
            logger.warning("Skipped (may already exist): %s", feed["name"])
            skipped += 1

    logger.info("Done: %d feeds added, %d skipped", success, skipped)


def sync_all() -> None:
    """Trigger a sync for all enabled feeds."""
    response = _api_request("GET", "/feeds/index")
    feeds = response if isinstance(response, list) else response.get("Feed", [])
    enabled_feeds = [f.get("Feed", f) for f in feeds if f.get("Feed", f).get("enabled")]

    if not enabled_feeds:
        logger.info("No enabled feeds to sync.")
        return

    logger.info("Syncing %d enabled feeds...", len(enabled_feeds))
    for feed in enabled_feeds:
        feed_id = feed.get("id")
        name = feed.get("name", "unknown")
        try:
            _api_request("GET", f"/feeds/fetchFromFeed/{feed_id}")
            logger.info("[OK] Sync triggered: [%s] %s", feed_id, name)
            time.sleep(1)  # Stagger syncs to avoid overloading
        except SystemExit:
            logger.warning("[WARN] Sync failed: [%s] %s", feed_id, name)

    logger.info("All sync jobs dispatched. Check MISP -> Feeds for progress.")


def sync_feed(feed_id: str) -> None:
    """Trigger sync for a specific feed by ID."""
    _api_request("GET", f"/feeds/fetchFromFeed/{feed_id}")
    logger.info("[OK] Sync triggered for feed ID: %s", feed_id)


def add_custom_feed(url: str, name: str, provider: str, fmt: str) -> None:
    """Add a custom feed by URL."""
    payload = {
        "Feed": {
            "name": name,
            "url": url,
            "provider": provider,
            "input_source": "network",
            "source_format": fmt,
            "enabled": True,
            "caching_enabled": True,
            "lookup_visible": True,
        }
    }
    response = _api_request("POST", "/feeds/add", payload)
    feed_id = response.get("Feed", {}).get("id", "?")
    logger.info("[OK] Custom feed added: ID=%s - %s", feed_id, name)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="MISP Feed Automation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--enable-defaults",
        action="store_true",
        help="Enable all recommended OSINT feeds",
    )
    parser.add_argument(
        "--list-feeds",
        action="store_true",
        help="List all configured feeds",
    )
    parser.add_argument(
        "--sync-all",
        action="store_true",
        help="Trigger sync for all enabled feeds",
    )
    parser.add_argument(
        "--sync-feed",
        metavar="FEED_ID",
        help="Sync a specific feed by ID",
    )
    parser.add_argument(
        "--add-feed",
        metavar="URL",
        help="Add a custom feed by URL",
    )
    parser.add_argument(
        "--feed-name",
        default="Custom Feed",
        help="Name for the custom feed (used with --add-feed)",
    )
    parser.add_argument(
        "--feed-provider",
        default="Custom",
        help="Provider name for the custom feed (used with --add-feed)",
    )
    parser.add_argument(
        "--feed-format",
        default="misp",
        choices=["misp", "text", "csv", "freetext"],
        help="Feed format (default: misp)",
    )

    args = parser.parse_args()

    if args.enable_defaults:
        enable_defaults()
    elif args.list_feeds:
        list_feeds()
    elif args.sync_all:
        sync_all()
    elif args.sync_feed:
        sync_feed(args.sync_feed)
    elif args.add_feed:
        add_custom_feed(args.add_feed, args.feed_name, args.feed_provider, args.feed_format)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
