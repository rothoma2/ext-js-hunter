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
from tabulate import tabulate
import urllib.request
from pprint import pprint

import tempfile
import os

def run_amass(domain: str) -> List[str]:
    """Run Amass in passive mode and return a list of subdomains."""
    try:
        result = subprocess.run(
            ["amass", "enum", "-d", domain, "--passive"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        result_domains = subprocess.run(
            ["amass", "db", "-names", "-d", domain],
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

    for line in result_domains.stdout.splitlines():
        line = line.strip()
        if line and not line.startswith("*"):
            subdomains.add(line)

    print(f"Results Found {len(subdomains)}")
    return sorted(subdomains)


def massdns_scan(domains: List[str], resolvers_path: str, massdns_path: str = "massdns", output_file: str = "results.txt") -> List[dict]:
    """
    Write domains to a temp file, run massdns, parse output, and return resolved domains as a list of dicts.
    """
    import re
    results = []
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmp:
        for d in domains:
            tmp.write(d + "\n")
        tmp_path = tmp.name

    try:
        cmd = [
            massdns_path,
            "-r", resolvers_path,
            "-t", "A",
            "-o", "S",
            "-w", output_file,
            tmp_path
        ]
        subprocess.run(cmd, check=True)

    except FileNotFoundError:
        print("massdns is not installed or not found in PATH.")
        os.unlink(tmp_path)
        return []
    except subprocess.CalledProcessError as exc:
        print(f"massdns failed: {exc}")
        os.unlink(tmp_path)
        return []

    # Parse massdns output
    pattern = re.compile(r"^(\S+)\.\s+A\s+(\S+)")
    with open(output_file, "r") as f:
        for line in f:
            m = pattern.match(line)
            if m:
                results.append({"domain": m.group(1), "ip": m.group(2)})

    os.unlink(tmp_path)
    return results


def lookup_asn_nc(ips: list[str], nc_path: str = "nc") -> dict:
    """
    Write IPs to a temp file, run the Cymru whois lookup via netcat, and parse the output into a dict.
    Returns: {ip: {asn, asn_name, country}}
    """
    import shlex
    import tempfile
    import re
    asn_info = {}
    if not ips:
        return asn_info
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tmp:
        for ip in ips:
            tmp.write(ip + "\n")
        tmp_path = tmp.name

    # Compose the shell command
    # { printf "begin\nverbose\n"; cat ips.txt; printf "end\n"; } | nc whois.cymru.com 43
    cmd = f'{{ printf "begin\nverbose\n"; cat {shlex.quote(tmp_path)}; printf "end\n"; }} | {shlex.quote(nc_path)} whois.cymru.com 43'
    try:
        result = subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout
    except Exception as e:
        print(f"ASN lookup via nc failed: {e}")
        os.unlink(tmp_path)
        return asn_info
    finally:
        os.unlink(tmp_path)

    # Parse output
    # Skip header lines, parse lines like: ASN | IP | BGP Prefix | CC | Registry | Allocated | AS Name
    for line in output.splitlines():
        if line.startswith("AS") or line.strip() == "" or line.startswith("Bulk mode"):
            continue
        parts = [x.strip() for x in line.split("|")]
        if len(parts) >= 7:
            asn, ip, bgp_prefix, cc, registry, allocated, as_name = parts[:7]
            asn_info[ip] = {"asn": asn, "asn_name": as_name, "country": cc}
    return asn_info

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

    print(f"Enumerating subdomains for {args.domain}...")
    subdomains = run_amass(args.domain)

    # Example usage of massdns_scan
    resolvers_path = "/home/robert/Documents/git/massdns/lists/resolvers.txt"  # Adjust as needed
    massdns_results = massdns_scan(subdomains, resolvers_path)


    if massdns_results:
        unique_ips = list({r["ip"] for r in massdns_results if r.get("ip")})
        asn_map = lookup_asn_nc(unique_ips)
        for r in massdns_results:
            ip = r.get("ip")
            asn_data = asn_map.get(ip, {})
            r["asn"] = asn_data.get("asn", "")
            r["asn_name"] = asn_data.get("asn_name", "")
            r["country"] = asn_data.get("country", "")
        print("\nResolved domains with ASN info:")
        print(tabulate(massdns_results, headers="keys", tablefmt="github"))
    else:
        print("No domains resolved by massdns.")




if __name__ == "__main__":
    main()
