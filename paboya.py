# PABOYA FINAL VERSION
# Header Simple + Semua Fungsi Digabung

import os
import sys
import socket
import requests
from concurrent.futures import ThreadPoolExecutor

class Colors:
    RED = "\033[31m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    END = "\033[0m"


def print_header():
    """Header simpel warna merah & putih"""
    print(f"{Colors.RED}{Colors.BOLD}=============================={Colors.END}")
    print(f"{Colors.RED}{Colors.BOLD}      P A B O Y A  v1.0       {Colors.END}")
    print(f"{Colors.WHITE}   Powerful Recon Tool by iyanji{Colors.END}")
    print(f"{Colors.RED}{Colors.BOLD}=============================={Colors.END}\n")


# ==========================
#   SUBDOMAIN ENUMERATION
# ==========================

def load_wordlist(filepath):
    try:
        with open(filepath, 'r') as f:
            return [line.strip() for line in f]
    except:
        print("Wordlist tidak ditemukan.")
        return []


def check_subdomain(domain, sub):
    target = f"{sub}.{domain}"
    try:
        socket.gethostbyname(target)
        print(f"[FOUND] {target}")
        return target
    except:
        return None


def enum_subdomains(domain, wordlist):
    print("\n[+] Memulai enumerasi subdomain...\n")
    found = []
    with ThreadPoolExecutor(max_workers=20) as exe:
        results = exe.map(lambda s: check_subdomain(domain, s), wordlist)
    for r in results:
        if r:
            found.append(r)
    return found


# ==========================
#     IP INFORMATION
# ==========================

def get_ip_info(ip):
    try:
        url = f"https://ipinfo.io/{ip}/json"
        r = requests.get(url, timeout=5)
        return r.json()
    except:
        return {"error": "Tidak bisa mengambil info IP"}


# ==========================
#        SAVE RESULTS
# ==========================

def save_output(filename, data):
    try:
        with open(filename, "w") as f:
            f.write(data)
        print(f"\n[+] Hasil disimpan ke: {filename}\n")
    except:
        print("Gagal menyimpan file.")


# ==========================
#            MAIN
# ==========================

def main():
    print_header()

    domain = input("Masukkan domain target: ")
    wordlist_path = input("Masukkan path wordlist: ")

    wl = load_wordlist(wordlist_path)
    subs = enum_subdomains(domain, wl)

    print("\n[+] Subdomain ditemukan:")
    for s in subs:
        print(" -", s)

    ip = input("\nCek info IP (opsional, tekan ENTER untuk skip): ")
    if ip:
        info = get_ip_info(ip)
        print("\n[+] Informasi IP:")
        print(info)

    out = input("\nNama file output (misal: hasil.txt): ")
    if out:
        content = "SUBDOMAIN FOUND:\n" + "\n".join(subs)
        if ip:
            content += f"\n\nIP INFO:\n{info}\n"
        save_output(out, content)


if __name__ == "__main__":
    main()
