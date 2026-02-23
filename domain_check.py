#!/usr/bin/env python3
"""
Domain availability checker using RDAP.
Checks a word list against multiple TLDs and reports what's available.

Usage:
    python3 domain_check.py                          # uses domain_words.json
    python3 domain_check.py --words=mywords.json     # use a different words file
    python3 domain_check.py words.txt                # load words from plain text file (one per line)
    python3 domain_check.py words.txt --tlds com,ai,app,io

RDAP returns:
    200 = registered (taken)
    404 = not found (likely available)
"""

import sys
import time
import csv
import json
import requests
from datetime import datetime
from itertools import product
from pathlib import Path

# ── Configuration ─────────────────────────────────────────────────────────────

TLDS = ["com", "ai", "app", "io", "co"]

# RDAP servers per TLD — sourced from IANA bootstrap: https://data.iana.org/rdap/dns.json
# Note: .io and .co are ccTLDs with no RDAP support — checked via WHOIS fallback below
RDAP_SERVERS = {
    "com":  "https://rdap.verisign.com/com/v1/domain/",
    "net":  "https://rdap.verisign.com/net/v1/domain/",
    "org":  "https://rdap.publicinterestregistry.org/rdap/domain/",
    "ai":   "https://rdap.identitydigital.services/rdap/domain/",
    "app":  "https://pubapi.registry.google/rdap/domain/",
    "dev":  "https://pubapi.registry.google/rdap/domain/",
    "tech": "https://rdap.centralnic.com/tech/domain/",
}

# WHOIS fallback for TLDs without RDAP (host, port)
WHOIS_SERVERS = {
    "io":  ("whois.nic.io", 43),
    "co":  ("whois.nic.co", 43),
    "me":  ("whois.nic.me", 43),
}

# Seconds between requests — be polite to RDAP servers
RATE_LIMIT = 0.4

# ── Word list ──────────────────────────────────────────────────────────────────

WORDS_FILE = Path(__file__).parent / "domain_words.json"

def load_words_file(path: Path) -> tuple[list[str], list[str], list[str]]:
    """Load words, prefixes, and roots from a JSON file."""
    with open(path) as f:
        data = json.load(f)
    return data.get("words", []), data.get("prefixes", []), data.get("roots", [])

def generate_combinations(prefixes, roots):
    return [f"{p}{r}" for p, r in product(prefixes, roots)]

# ── Core logic ─────────────────────────────────────────────────────────────────

def check_whois(domain: str, host: str, port: int = 43) -> str:
    """WHOIS fallback for TLDs without RDAP. Returns 'available', 'taken', or 'unknown'."""
    import socket
    try:
        with socket.create_connection((host, port), timeout=8) as sock:
            sock.sendall(f"{domain}\r\n".encode())
            response = b""
            while chunk := sock.recv(4096):
                response += chunk
        text = response.decode(errors="ignore").lower()
        if "no match" in text or "not found" in text or "no data found" in text:
            return "available"
        elif "domain name:" in text or "registrar:" in text or "registered" in text:
            return "taken"
        return "unknown"
    except Exception:
        return "error"


def check_domain(word: str, tld: str, session: requests.Session) -> str:
    """
    Returns 'available', 'taken', or 'unknown'.
    Uses RDAP (preferred) or WHOIS fallback.
    RDAP: 404 = not registered, 200 = registered.
    """
    domain = f"{word}.{tld}"

    # Try RDAP first
    rdap_base = RDAP_SERVERS.get(tld)
    if rdap_base:
        url = f"{rdap_base}{domain}"
        try:
            resp = session.get(url, timeout=8)
            if resp.status_code == 404:
                return "available"
            elif resp.status_code == 200:
                return "taken"
            else:
                return f"unknown({resp.status_code})"
        except requests.exceptions.Timeout:
            return "timeout"
        except requests.exceptions.RequestException:
            return "error"

    # WHOIS fallback
    whois = WHOIS_SERVERS.get(tld)
    if whois:
        return check_whois(domain, *whois)

    return "no-server"


def run(words: list[str], tlds: list[str], save_csv: bool = True):
    available = []
    taken = []
    unknown = []

    session = requests.Session()
    session.headers.update({"User-Agent": "domain-availability-checker/1.0"})

    total = len(words) * len(tlds)
    checked = 0

    print(f"\nChecking {len(words)} words × {len(tlds)} TLDs = {total} domains\n")
    print(f"{'Domain':<30} {'Status'}")
    print("─" * 45)

    for word in words:
        for tld in tlds:
            domain = f"{word}.{tld}"
            status = check_domain(word, tld, session)
            checked += 1

            if status == "available":
                marker = "✓"
                available.append(domain)
            elif status == "taken":
                marker = "✗"
                taken.append(domain)
            else:
                marker = "?"
                unknown.append(domain)

            # Only print available loudly, suppress noise for taken
            if status == "available":
                print(f"{marker} AVAILABLE  {domain}")
            elif status != "taken":
                print(f"{marker} {status:<10} {domain}")

            time.sleep(RATE_LIMIT)

    # Summary
    print("\n" + "═" * 45)
    print(f"Checked:   {checked}")
    print(f"Available: {len(available)}")
    print(f"Taken:     {len(taken)}")
    print(f"Unknown:   {len(unknown)}")

    if available:
        print("\n── Available domains ──────────────────────")
        for d in available:
            print(f"  ✓ {d}")

    # Save results to CSV
    if save_csv and (available or unknown):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"domain_results_{ts}.csv"
        with open(filename, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["domain", "status"])
            for d in available:
                writer.writerow([d, "available"])
            for d in taken:
                writer.writerow([d, "taken"])
            for d in unknown:
                writer.writerow([d, "unknown"])
        print(f"\nResults saved to {filename}")


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    words_file = WORDS_FILE
    for arg in sys.argv[1:]:
        if arg.startswith("--words="):
            words_file = Path(arg.split("=", 1)[1])

    try:
        base_words, prefixes, roots = load_words_file(words_file)
        print(f"Loaded words from {words_file}")
    except FileNotFoundError:
        print(f"Words file not found: {words_file}")
        sys.exit(1)

    words = list(base_words)

    # Add generated combinations
    words += generate_combinations(prefixes, roots)

    # Parse args — separate flags from positional (file path)
    tlds = list(TLDS)
    file_path = None
    for arg in sys.argv[1:]:
        if arg.startswith("--tlds="):
            tlds = arg.split("=", 1)[1].split(",")
        elif arg.startswith("--words="):
            pass  # already handled above
        elif not arg.startswith("--"):
            file_path = arg

    # Optional: load words from file
    if file_path:
        try:
            with open(file_path) as f:
                file_words = [line.strip().lower() for line in f if line.strip()]
            print(f"Loaded {len(file_words)} words from {file_path}")
            words = file_words
        except FileNotFoundError:
            print(f"File not found: {file_path}")
            sys.exit(1)

    # Deduplicate, lowercase
    words = list(dict.fromkeys(w.lower() for w in words))

    run(words, tlds)
