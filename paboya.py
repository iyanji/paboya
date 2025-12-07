#!/usr/bin/env python3
"""
PABOYA - Powerful Subdomain and IP Reconnaissance Tool
Author : iyanji
"""

import requests
import socket
import threading
import concurrent.futures
import time
import sys
import os
from urllib.parse import urlparse
import dns.resolver
import json

# Warna untuk tampilan
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def print_banner():
    """Menampilkan banner yang garang"""
    banner = f"""
{Colors.RED}{Colors.BOLD}
██████╗  █████╗ ██████╗  ██████╗ ██╗   ██╗ █████╗ 
██╔══██╗██╔══██╗██╔══██╗██╔═══██╗╚██╗ ██╔╝██╔══██╗
██████╔╝███████║██████╔╝██║   ██║ ╚████╔╝ ███████║
██╔══██╗██╔══██║██╔══██╗██║   ██║  ╚██╔╝  ██╔══██║
██████╔╝██║  ██║██████╔╝╚██████╔╝   ██║   ██║  ██║
╚═════╝ ╚═╝  ╚═╝╚═════╝  ╚═════╝    ╚═╝   ╚═╝  ╚═╝
{Colors.END}
{Colors.RED}{Colors.BOLD}          P O W E R F U L   R E C O N   T O O L{Colors.END}
{Colors.YELLOW}           Author : iyanji{Colors.END}
{Colors.CYAN}    Subdomain Enumeration & IP Analysis{Colors.END}
"""
    print(banner)

def get_subdomains(domain):
    """Mengumpulkan subdomain dari berbagai sumber"""
    print(f"{Colors.BLUE}{Colors.BOLD}[+] Memulai pengumpulan subdomain...{Colors.END}")
    
    subdomains = set()
    
    # Common subdomain wordlist
    common_subs = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
        'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
        'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3',
        'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static',
        'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki',
        'web', 'media', 'email', 'images', 'img', 'www1', 'intranet', 'portal',
        'video', 'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4', 'www3',
        'chat', 'search', 'apps', 'download', 'upload', 'redirect', 'proxy',
        'ads', 'photo', 'signin', 'ssl', 'payment', 'payments', 'checkout',
        'register', 'auth', 'remote', 'files', 'live', 'content', 'sites',
        'data', 'help', 'get', 'img0', 'img1', 'img2', 'css0', 'css1', 'css2',
        'js0', 'js1', 'js2', 'cdn0', 'cdn1', 'cdn2', 'cdn3', 'origin', 'edge',
        'api1', 'api2', 'api3', 'graphql', 'rest', 'soap', 'rpc', 'staging',
        'preprod', 'production', 'prod', 'development', 'dev1', 'dev2', 'test1',
        'test2', 'qa', 'quality', 'uat', 'preview', 'review', 'backup', 'bak',
        'archive', 'old', 'legacy', 'classic', 'new', 'next', 'future', 'v1',
        'v2', 'v3', 'version1', 'version2', 'version3', 'latest', 'current',
        'previous', 'stage', 'demo1', 'demo2', 'sandbox', 'playground', 'lab',
        'labs', 'research', 'study', 'experiment', 'trial', 'pilot', 'temp',
        'temporary', 'tmp', 'cache', 'cached', 'mirror', 'mirrors', 'clone',
        'clones', 'backup1', 'backup2', 'backup3', 'replica', 'replicas',
        'sync', 'synch', 'synchronization', 'async', 'asynchronous', 'stream',
        'streaming', 'broadcast', 'multicast', 'unicast', 'peer', 'peers',
        'node', 'nodes', 'cluster', 'clusters', 'grid', 'cloud', 'fog', 'edge',
        'compute', 'processor', 'engine', 'servers', 'services', 'microservices',
        'lambda', 'function', 'functions', 'gateway', 'gateways', 'router',
        'routers', 'switch', 'switches', 'bridge', 'bridges', 'hub', 'hubs',
        'spoke', 'spokes', 'wheel', 'wheels', 'core', 'cores', 'central',
        'center', 'centres', 'regional', 'region', 'regions', 'zone', 'zones',
        'area', 'areas', 'district', 'districts', 'sector', 'sectors', 'segment',
        'segments', 'block', 'blocks', 'cell', 'cells', 'unit', 'units', 'module',
        'modules', 'component', 'components', 'element', 'elements', 'feature',
        'features', 'functionality', 'capability', 'capabilities', 'resource',
        'resources', 'asset', 'assets', 'property', 'properties', 'entity',
        'entities', 'object', 'objects', 'item', 'items', 'entry', 'entries',
        'record', 'records', 'document', 'documents', 'file', 'files', 'folder',
        'folders', 'directory', 'directories', 'path', 'paths', 'route', 'routes',
        'channel', 'channels', 'pipe', 'pipes', 'queue', 'queues', 'stack',
        'stacks', 'heap', 'heaps', 'pool', 'pools', 'buffer', 'buffers', 'cache',
        'caches', 'memory', 'storage', 'store', 'stores', 'repository', 'repositories',
        'registry', 'registries', 'catalog', 'catalogs', 'inventory', 'inventories',
        'database', 'databases', 'db', 'dbs', 'table', 'tables', 'row', 'rows',
        'column', 'columns', 'field', 'fields', 'index', 'indexes', 'key', 'keys',
        'value', 'values', 'pair', 'pairs', 'tuple', 'tuples', 'set', 'sets',
        'list', 'lists', 'array', 'arrays', 'vector', 'vectors', 'matrix', 'matrices',
        'graph', 'graphs', 'tree', 'trees', 'node', 'nodes', 'leaf', 'leaves',
        'branch', 'branches', 'root', 'roots', 'trunk', 'trunks', 'stem', 'stems',
        'flower', 'flowers', 'fruit', 'fruits', 'seed', 'seeds', 'spore', 'spores',
        'pollen', 'pollens', 'nectar', 'nectars', 'honey', 'honeys', 'wax', 'waxes',
        'resin', 'resins', 'sap', 'saps', 'latex', 'latexes', 'rubber', 'rubbers',
        'plastic', 'plastics', 'polymer', 'polymers', 'monomer', 'monomers',
        'dimer', 'dimers', 'trimer', 'trimers', 'tetramer', 'tetramers',
        'pentamer', 'pentamers', 'hexamer', 'hexamers', 'heptamer', 'heptamers',
        'octamer', 'octamers', 'nonamer', 'nonamers', 'decamer', 'decamers'
    ]
    
    # Generate subdomains dari wordlist
    for sub in common_subs:
        subdomains.add(f"{sub}.{domain}")
    
    # Tambahkan domain utama
    subdomains.add(domain)
    
    # Coba resolusi DNS untuk subdomain umum
    print(f"{Colors.YELLOW}[*] Melakukan resolusi DNS untuk subdomain umum...{Colors.END}")
    
    resolved_subs = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        future_to_sub = {executor.submit(resolve_dns, sub): sub for sub in subdomains}
        for future in concurrent.futures.as_completed(future_to_sub):
            sub = future_to_sub[future]
            try:
                result = future.result()
                if result:
                    resolved_subs.add(sub)
                    print(f"{Colors.GREEN}[+] Ditemukan: {sub}{Colors.END}")
            except:
                pass
    
    return sorted(resolved_subs)

def resolve_dns(hostname):
    """Resolve DNS untuk hostname"""
    try:
        socket.gethostbyname(hostname)
        return True
    except:
        return False

def get_ip_addresses(subdomains):
    """Mengumpulkan IP address untuk setiap subdomain"""
    print(f"\n{Colors.BLUE}{Colors.BOLD}[+] Memulai scan IP subdomain...{Colors.END}")
    
    ip_results = {}
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        future_to_sub = {executor.submit(get_ip_info, sub): sub for sub in subdomains}
        for future in concurrent.futures.as_completed(future_to_sub):
            sub = future_to_sub[future]
            try:
                ips, cname = future.result()
                if ips:
                    ip_results[sub] = {
                        'ips': ips,
                        'cname': cname
                    }
                    print(f"{Colors.GREEN}[+] {sub} -> {', '.join(ips)}{Colors.END}")
                    if cname:
                        print(f"{Colors.YELLOW}    CNAME: {cname}{Colors.END}")
            except Exception as e:
                print(f"{Colors.RED}[-] Error pada {sub}: {str(e)}{Colors.END}")
    
    return ip_results

def get_ip_info(hostname):
    """Mendapatkan informasi IP dan CNAME untuk hostname"""
    try:
        # Resolve A records
        answers = dns.resolver.resolve(hostname, 'A')
        ips = [str(rdata) for rdata in answers]
        
        # Coba resolve CNAME
        cname = None
        try:
            cname_answers = dns.resolver.resolve(hostname, 'CNAME')
            cname = str(cname_answers[0].target)
        except:
            pass
            
        return ips, cname
    except Exception as e:
        return [], None

def check_ip_access(ip_results):
    """Memeriksa akses IP dan status code"""
    print(f"\n{Colors.BLUE}{Colors.BOLD}[+] Memulai scan IP access dan status code...{Colors.END}")
    
    access_results = {}
    
    for subdomain, info in ip_results.items():
        access_results[subdomain] = {
            'ips': info['ips'],
            'cname': info['cname'],
            'ip_details': []
        }
        
        print(f"\n{Colors.CYAN}[*] Memeriksa {subdomain}{Colors.END}")
        
        for ip in info['ips']:
            ip_detail = check_single_ip(ip, subdomain)
            access_results[subdomain]['ip_details'].append(ip_detail)
            
            # Tampilkan hasil
            status_color = Colors.GREEN if ip_detail['http_status'] == 200 else Colors.YELLOW if ip_detail['http_status'] in [301, 302] else Colors.RED
            print(f"    {Colors.WHITE}IP: {ip:<15} | HTTP: {status_color}{ip_detail['http_status']}{Colors.WHITE} | HTTPS: {status_color}{ip_detail['https_status']}{Colors.WHITE} | Origin: {Colors.GREEN if ip_detail['is_origin'] else Colors.RED}{ip_detail['is_origin']}{Colors.WHITE} | CDN: {Colors.RED if ip_detail['is_cdn'] else Colors.GREEN}{ip_detail['is_cdn']}{Colors.END}")
    
    return access_results

def check_single_ip(ip, subdomain):
    """Memeriksa akses single IP"""
    ip_detail = {
        'ip': ip,
        'http_status': 0,
        'https_status': 0,
        'is_origin': False,
        'is_cdn': False,
        'response_time': 0
    }
    
    # Check HTTP
    try:
        start_time = time.time()
        response = requests.get(
            f"http://{ip}",
            headers={'Host': subdomain},
            timeout=5,
            verify=False,
            allow_redirects=False
        )
        ip_detail['http_status'] = response.status_code
        ip_detail['response_time'] = int((time.time() - start_time) * 1000)
    except:
        ip_detail['http_status'] = 0
    
    # Check HTTPS
    try:
        start_time = time.time()
        response = requests.get(
            f"https://{ip}",
            headers={'Host': subdomain},
            timeout=5,
            verify=False,
            allow_redirects=False
        )
        ip_detail['https_status'] = response.status_code
        if ip_detail['response_time'] == 0:
            ip_detail['response_time'] = int((time.time() - start_time) * 1000)
    except:
        ip_detail['https_status'] = 0
    
    # Deteksi CDN dan Origin
    ip_detail['is_cdn'] = detect_cdn(ip, subdomain)
    ip_detail['is_origin'] = not ip_detail['is_cdn']
    
    return ip_detail

def detect_cdn(ip, subdomain):
    """Mendeteksi apakah IP termasuk CDN"""
    cdn_ranges = [
        '104.16.0.0/12',  # Cloudflare
        '172.64.0.0/13',  # Cloudflare
        '173.245.48.0/20', # Cloudflare
        '131.0.72.0/22',  # Cloudflare
        '190.93.240.0/20', # Cloudflare
        '13.32.0.0/15',   # Amazon CloudFront
        '13.35.0.0/16',   # Amazon CloudFront
        '13.224.0.0/14',  # Amazon CloudFront
        '34.192.0.0/12',  # Amazon CloudFront
        '52.124.128.0/17', # Amazon CloudFront
        '54.230.0.0/16',  # Amazon CloudFront
        '150.197.0.0/16', # Akamai
        '104.64.0.0/10',  # Akamai
        '23.0.0.0/12',    # Akamai
        '184.24.0.0/13',  # Akamai
        '2.16.0.0/13',    # Akamai
        '95.100.0.0/15',  # Fastly
        '23.235.32.0/20', # Fastly
        '199.27.72.0/21', # Fastly
        '185.31.16.0/22', # Google Cloud CDN
        '130.211.0.0/16', # Google Cloud CDN
        '8.8.8.8/16',     # Google
        '8.34.0.0/16',    # Google
        '8.35.0.0/16',    # Google
    ]
    
    # Simple detection based on common CDN IP ranges
    ip_parts = list(map(int, ip.split('.')))
    
    # Cloudflare detection
    if (ip_parts[0] == 104 and 16 <= ip_parts[1] <= 31) or \
       (ip_parts[0] == 172 and ip_parts[1] == 64) or \
       (ip_parts[0] == 173 and ip_parts[1] == 245 and 48 <= ip_parts[2] <= 63):
        return True
    
    # Amazon CloudFront detection
    if (ip_parts[0] == 13 and (32 <= ip_parts[1] <= 33 or ip_parts[1] == 35 or 224 <= ip_parts[1] <= 227)) or \
       (ip_parts[0] == 34 and 192 <= ip_parts[1] <= 207) or \
       (ip_parts[0] == 52 and ip_parts[1] == 124 and 128 <= ip_parts[2] <= 255) or \
       (ip_parts[0] == 54 and ip_parts[1] == 230):
        return True
    
    # Check server headers for CDN indicators
    try:
        response = requests.get(
            f"http://{ip}",
            headers={'Host': subdomain},
            timeout=3,
            verify=False
        )
        headers = response.headers
        
        cdn_indicators = ['cloudflare', 'cloudfront', 'akamai', 'fastly', 'google', 'incapsula']
        for header in headers.values():
            if any(indicator in header.lower() for indicator in cdn_indicators):
                return True
    except:
        pass
    
    return False

def display_final_results(access_results):
    """Menampilkan hasil akhir dalam format yang rapi"""
    print(f"\n{Colors.RED}{Colors.BOLD}" + "="*100 + Colors.END)
    print(f"{Colors.RED}{Colors.BOLD}FINAL RESULTS - SUBDOMAIN : IP ADDRESS - STATUS CODE - CDN/ORIGIN{Colors.END}")
    print(f"{Colors.RED}{Colors.BOLD}" + "="*100 + Colors.END)
    
    for subdomain, info in access_results.items():
        print(f"\n{Colors.CYAN}{Colors.BOLD}┌─ {subdomain}{Colors.END}")
        if info['cname']:
            print(f"{Colors.YELLOW}│ CNAME: {info['cname']}{Colors.END}")
        
        for ip_detail in info['ip_details']:
            # Tentukan status code yang akan ditampilkan (prioritaskan HTTPS jika available)
            status_code = ip_detail['https_status'] if ip_detail['https_status'] > 0 else ip_detail['http_status']
            
            # Tentukan warna status code
            if status_code == 200:
                status_color = Colors.GREEN
                status_text = "200 OK"
            elif status_code in [301, 302]:
                status_color = Colors.YELLOW
                status_text = f"{status_code} Redirect"
            elif status_code in [403, 404]:
                status_color = Colors.RED
                status_text = f"{status_code} Error"
            elif status_code == 0:
                status_color = Colors.RED
                status_text = "Timeout/Error"
            else:
                status_color = Colors.YELLOW
                status_text = str(status_code)
            
            # Tentukan jenis IP
            ip_type = "ORIGIN" if ip_detail['is_origin'] else "CDN"
            ip_type_color = Colors.GREEN if ip_detail['is_origin'] else Colors.RED
            
            print(f"{Colors.WHITE}├─ {ip_detail['ip']:<15} {Colors.WHITE}- {status_color}{status_text:<12} {Colors.WHITE}- {ip_type_color}{ip_type}{Colors.END}")

def save_results(domain, subdomains, ip_results, access_results):
    """Menyimpan hasil ke file"""
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    filename = f"paboya_{domain}_{timestamp}.txt"
    
    with open(filename, 'w') as f:
        f.write(f"PABOYA Scan Results\n")
        f.write(f"Target: {domain}\n")
        f.write(f"Scan Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Author: iyanji\n")
        f.write("="*80 + "\n\n")
        
        f.write("SUBDOMAIN ENUMERATION\n")
        f.write("="*50 + "\n")
        for i, sub in enumerate(subdomains, 1):
            f.write(f"{i:3d}. {sub}\n")
        
        f.write("\n\nIP SCAN RESULTS\n")
        f.write("="*50 + "\n")
        for sub, info in ip_results.items():
            f.write(f"\n{sub}:\n")
            f.write(f"  IPs: {', '.join(info['ips'])}\n")
            if info['cname']:
                f.write(f"  CNAME: {info['cname']}\n")
        
        f.write("\n\nFINAL RESULTS - SUBDOMAIN : IP ADDRESS - STATUS CODE - CDN/ORIGIN\n")
        f.write("="*80 + "\n")
        for sub, info in access_results.items():
            f.write(f"\n{sub}\n")
            if info['cname']:
                f.write(f"  CNAME: {info['cname']}\n")
            
            for ip_detail in info['ip_details']:
                status_code = ip_detail['https_status'] if ip_detail['https_status'] > 0 else ip_detail['http_status']
                ip_type = "ORIGIN" if ip_detail['is_origin'] else "CDN"
                f.write(f"  {ip_detail['ip']:<15} - {status_code:<6} - {ip_type}\n")
    
    print(f"\n{Colors.GREEN}{Colors.BOLD}[+] Hasil disimpan di: {filename}{Colors.END}")

def main():
    """Fungsi utama"""
    print_banner()
    
    try:
        # Input target
        target = input(f"{Colors.WHITE}{Colors.BOLD}Target : {Colors.END}").strip()
        
        if not target:
            print(f"{Colors.RED}[!] Target tidak boleh kosong!{Colors.END}")
            return
        
        # Validasi target
        if not (target.startswith('http://') or target.startswith('https://')):
            target = 'https://' + target
        
        parsed = urlparse(target)
        domain = parsed.netloc or parsed.path
        
        if not domain:
            print(f"{Colors.RED}[!] Domain tidak valid!{Colors.END}")
            return
        
        print(f"\n{Colors.MAGENTA}{Colors.BOLD}[*] Memulai scan untuk: {domain}{Colors.END}")
        
        # Step 1: Subdomain Enumeration
        print(f"\n{Colors.RED}{Colors.BOLD}> Subdomain{Colors.END}")
        subdomains = get_subdomains(domain)
        
        if not subdomains:
            print(f"{Colors.RED}[-] Tidak ada subdomain yang ditemukan!{Colors.END}")
            return
        
        print(f"\n{Colors.GREEN}[+] Ditemukan {len(subdomains)} subdomain{Colors.END}")
        
        # Step 2: IP Scan
        print(f"\n{Colors.RED}{Colors.BOLD}> Scan IP Subdomain{Colors.END}")
        ip_results = get_ip_addresses(subdomains)
        
        if not ip_results:
            print(f"{Colors.RED}[-] Tidak ada IP yang ditemukan!{Colors.END}")
            return
        
        # Step 3: IP Access Analysis
        print(f"\n{Colors.RED}{Colors.BOLD}> Scan IP Access{Colors.END}")
        access_results = check_ip_access(ip_results)
        
        # Tampilkan hasil akhir
        display_final_results(access_results)
        
        # Save results
        save_results(domain, subdomains, ip_results, access_results)
        
        # Summary
        print(f"\n{Colors.GREEN}{Colors.BOLD}[+] Scan selesai!{Colors.END}")
        print(f"{Colors.CYAN}[*] Total subdomain: {len(subdomains)}{Colors.END}")
        print(f"{Colors.CYAN}[*] Total IP yang di-scan: {sum(len(info['ips']) for info in ip_results.values())}{Colors.END}")
        
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Scan dihentikan oleh user{Colors.END}")
    except Exception as e:
        print(f"\n{Colors.RED}[!] Error: {str(e)}{Colors.END}")

if __name__ == "__main__":
    # Install dependencies jika diperlukan
    try:
        import dns.resolver
    except ImportError:
        print(f"{Colors.RED}[!] Menginstall dependencies...{Colors.END}")
        os.system("pip install dnspython requests")
        print(f"{Colors.GREEN}[+] Dependencies terinstall!{Colors.END}")
    
    main()
