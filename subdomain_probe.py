#!/usr/bin/env python3
"""Prototype script to enumerate and probe subdomains.

Given a base domain, the script uses the Amass tool to enumerate
potential subdomains. For each discovered subdomain it attempts to
resolve the domain to an IP address and performs a simple HTTPS GET
request to verify connectivity.
"""

from __future__ import annotations

import argparse
import socket
import subprocess
from typing import List, Optional
import ssl
import urllib.request


def run_amass(domain: str) -> List[str]:
    """Run Amass in passive mode and return a list of subdomains."""
    try:
        result = subprocess.run(
            ["amass", "enum", "-passive", "-d", domain],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError:
        print("Amass is not installed or not found in PATH.")
        return []
    except subprocess.CalledProcessError as exc:
        print(f"Amass failed: {exc.stderr.strip()}")
        return []

    subdomains = set()
    for line in result.stdout.splitlines():
        line = line.strip()
        if line and not line.startswith("*"):
            subdomains.add(line)
    return sorted(subdomains)


def resolve_domain(domain: str) -> Optional[str]:
    """Return the IP address for a domain or ``None`` if it fails to resolve."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def probe_https(domain: str) -> Optional[int]:
    """Attempt an HTTPS GET request and return the status code if successful."""
    context = ssl.create_default_context()
    url = f"https://{domain}"
    try:
        with urllib.request.urlopen(url, timeout=5, context=context) as resp:
            return resp.getcode()
    except Exception:
        return None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Enumerate subdomains with Amass and probe them via HTTPS."
    )
    parser.add_argument("domain", help="The base domain to enumerate")
    args = parser.parse_args()

    subdomains = run_amass(args.domain)
    for sub in subdomains:
        ip = resolve_domain(sub)
        status = probe_https(sub) if ip else None
        resolved = ip is not None
        print(f"{sub:40} resolved={resolved!s:5} status={status}")


if __name__ == "__main__":
    main()
