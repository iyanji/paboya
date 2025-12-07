#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import requests
import json
import socket
import re
import sys
from urllib.parse import urlparse

# ============================================================
# COLORS
# ============================================================
RED = "\033[91m"
WHITE = "\033[97m"
GREEN = "\033[92m"
BLACK = "\033[30m"
BG_GREEN = "\033[42m"
RESET = "\033[0m"

# ============================================================
# HEADER MERAH PUTIH
# ============================================================
def header():
    print(RED + "\n[ PABOYA ]" + RESET + WHITE + " Passive Bug Bounty Analyzer" + RESET)
    print(RED + "Author :" + RESET + WHITE + " iyanji" + RESET)
    print(RED + "-----------------------------------------------------\n" + RESET)

# ============================================================
# ARGUMENTS
# ============================================================
def get_args():
    parser = argparse.ArgumentParser(
        description="PABOYA – Passive Bug Bounty Analyzer by iyanji"
    )
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-o", "--output", help="Save result to file (txt/json)")
    parser.add_argument("--proxy", help="Proxy http://127.0.0.1:8080")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--silent", action="store_true")
    parser.add_argument("--no-cdn-check", action="store_true")
    return parser.parse_args()

# ============================================================
# SMART REQUEST HANDLER
# ============================================================
def req(url, timeout=10, proxy=None):
    try:
        s = requests.Session()
        if proxy:
            s.proxies = {"http": proxy, "https": proxy}
        r = s.get(url, timeout=timeout, verify=False, allow_redirects=True)
        return r
    except:
        return None

# ============================================================
# TABLE FORMATTER (HIJAU-HITAM)
# ============================================================
def print_table(title, rows):
    print(f"\n{GREEN}{title}{RESET}")
    if not rows:
        print("Tidak ada hasil.\n")
        return

    headers = rows[0].keys()

    # header
    line = ""
    for h in headers:
        line += f"{BG_GREEN}{BLACK} {h.upper()} {RESET}  "
    print(line)

    # rows
    for row in rows:
        out = ""
        for v in row.values():
            out += f"{v:<20} "
        print(out)
    print()

# ============================================================
# PASSIVE SUBDOMAIN ENUM
# ============================================================
def passive_subdomain(domain, timeout, proxy, silent=False):
    if not silent:
        print("[*] Passive Subdomain Enumeration...")
    subs = set()

    # CRTsh
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    r = req(url, timeout, proxy)
    if r and r.status_code == 200:
        try:
            for d in r.json():
                name = d.get("name_value", "")
                for s in name.split("\n"):
                    if domain in s:
                        subs.add(s.strip())
        except:
            pass

    # AlienVault
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    r = req(url, timeout, proxy)
    if r and r.status_code == 200:
        try:
            j = r.json().get("passive_dns", [])
            for d in j:
                host = d.get("hostname", "")
                if domain in host:
                    subs.add(host)
        except:
            pass

    # jl / bufferover
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    r = req(url, timeout, proxy)
    if r and r.status_code == 200:
        for line in r.text.splitlines():
            sp = line.split(",")
            if len(sp) > 1 and domain in sp[0]:
                subs.add(sp[0])

    final = sorted(list(subs))
    rows = [{"subdomain": s, "source": "passive"} for s in final]
    print_table("SUBDOMAIN", rows)
    return final

# ============================================================
# CDN CHECK
# ============================================================
def cdn_check(domain, timeout, proxy, silent=False):
    if silent:
        return None

    print("[*] Checking CDN...")

    target_ip = ""
    try:
        target_ip = socket.gethostbyname(domain)
    except:
        return None

    cdn = None
    patterns = {
        "Cloudflare": ["cloudflare", "cf-ray"],
        "Akamai": ["akamai"],
        "Fastly": ["fastly"],
        "Cloudfront": ["cloudfront"],
    }

    r = req("http://" + domain, timeout, proxy)
    if not r:
        return None

    server = r.headers.get("server", "").lower()
    via = r.headers.get("via", "").lower()

    for name, keys in patterns.items():
        for k in keys:
            if k in server or k in via:
                cdn = name

    rows = [{"cdn": cdn if cdn else "None", "ip": target_ip}]
    print_table("CDN DETECTION", rows)
    return cdn

# ============================================================
# ASN FINDER
# ============================================================
def asn_lookup(ip, timeout, proxy):
    url = f"https://api.hackertarget.com/aslookup/?q={ip}"
    r = req(url, timeout, proxy)
    if r and "AS" in r.text:
        return r.text.strip()
    return None

# ============================================================
# ORIGIN IP HUNTER
# ============================================================
def origin_ip(domain, timeout, proxy, silent=False):
    if not silent:
        print("[*] Origin IP Hunting...")

    ips = set()

    # Historical via hackertarget
    url = f"https://api.hackertarget.com/dnslookup/?q={domain}"
    r = req(url, timeout, proxy)
    if r:
        for line in r.text.splitlines():
            if "A" in line and domain in line:
                sp = line.split()
                if len(sp) > 2:
                    ip = sp[-1].strip()
                    if re.match(r"\d+\.\d+\.\d+\.\d+", ip):
                        ips.add(ip)

    final = sorted(list(ips))
    rows = [{"origin_ip": i, "method": "historical"} for i in final]
    print_table("ORIGIN IP", rows)
    return final

# ============================================================
# PANEL FINDER
# ============================================================
def panel_finder(domain, timeout, proxy, silent=False):
    if not silent:
        print("[*] Panel Finder...")

    paths = [
        "wp-admin", "wp-login.php", "admin", "login",
        "cpanel", "webmail", "whm",
        "directadmin", "plesk-login",
        "vesta", "hestia", "webmin"
    ]

    found = []

    for p in paths:
        url = f"http://{domain}/{p}"
        r = req(url, timeout, proxy)
        if r and r.status_code in [200, 301, 302, 401]:
            found.append({"panel": p, "status": r.status_code})

    print_table("PANEL", found)
    return found

# ============================================================
# TECH DETECTOR
# ============================================================
def tech_detector(domain, timeout, proxy):
    print("[*] Tech Detector...")

    r = req("http://" + domain, timeout, proxy)
    if not r:
        return []

    tech = set()

    headers = r.headers
    body = r.text.lower()

    checks = {
        "WordPress": "wp-content",
        "Laravel": "laravel_session",
        "Cloudflare": "cf-ray",
        "Bootstrap": "bootstrap.min.css",
        "jQuery": "jquery",
        "Nginx": "nginx",
        "Apache": "apache",
        "React": "react",
        "VueJS": "vue",
        "NextJS": "_next"
    }

    for name, sig in checks.items():
        if sig in str(headers).lower() or sig in body:
            tech.add(name)

    rows = [{"tech": t, "detected": "yes"} for t in tech]
    print_table("TECH STACK", rows)

    return list(tech)

# ============================================================
# LEAK FINDER (PUBLIC)
# ============================================================
def leak_search(domain, timeout, proxy):
    print("[*] Leak Finder...")

    leaks = []

    url = f"https://api.hackertarget.com/pagelinks/?q={domain}"
    r = req(url, timeout, proxy)
    if r:
        for line in r.text.splitlines():
            if "paste" in line or "github" in line:
                leaks.append({"leak": line[:60], "source": "public"})

    print_table("LEAKS", leaks)
    return leaks

# ============================================================
# SAVE FILE MANUAL (TXT/JSON)
# ============================================================
def save_file(filename, data):
    if filename.endswith(".json"):
        with open(filename, "w") as f:
            json.dump(data, f, indent=4)
    else:
        with open(filename, "w") as f:
            for d in data:
                f.write(str(d) + "\n")

    print(f"[+] Saved to {filename}")

# ============================================================
# MAIN
# ============================================================
def main():
    args = get_args()
    header()

    domain = args.domain
    proxy = args.proxy
    timeout = args.timeout

    print(f"Target  : {domain}")
    print(f"Timeout : {timeout}")
    print(f"Proxy   : {proxy if proxy else 'None'}")
    print("-----------------------------------------------------\n")

    # MAIN ENUMERATION
    subdomains = passive_subdomain(domain, timeout, proxy, args.silent)

    if not args.no_cdn_check:
        cdn = cdn_check(domain, timeout, proxy, args.silent)

    origin = origin_ip(domain, timeout, proxy, args.silent)
    panels = panel_finder(domain, timeout, proxy, args.silent)
    tech = tech_detector(domain, timeout, proxy)
    leaks = leak_search(domain, timeout, proxy)

    # SAVE OPTION
    if args.output:
        all_data = {
            "domain": domain,
            "subdomains": subdomains,
            "cdn": cdn if not args.no_cdn_check else "Skipped",
            "origin": origin,
            "panels": panels,
            "tech": tech,
            "leaks": leaks,
        }
        save_file(args.output, all_data)

# ============================================================
# RUN
# ============================================================
if __name__ == "__main__":
    main()
