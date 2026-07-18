#!/usr/bin/env python3
"""
Mirnov OSINT Ultimate v3.0
Author: usellts
Use only on targets you own or have explicit written permission to test.
"""

import sys
import time
import socket
import json
import threading
import os
import re
import hashlib
import urllib.parse
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

# ── optional deps ─────────────────────────────────────────────────────────────
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class Fore:
        RED=YELLOW=GREEN=CYAN=MAGENTA=WHITE=RESET=''
    class Style:
        RESET_ALL=''

try:
    from tqdm import tqdm
except ImportError:
    def tqdm(x, **kwargs): return x

try:
    import requests
    REQ_OK = True
except ImportError:
    REQ_OK = False
    print("[!] pip install requests")

try:
    import dns.resolver
    DNS_OK = True
except ImportError:
    DNS_OK = False

try:
    from fpdf import FPDF
    PDF_OK = True
except ImportError:
    PDF_OK = False

try:
    from googlesearch import search as google_search
    GOOGLE_OK = True
except ImportError:
    GOOGLE_OK = False

try:
    import whois as _whois
    WHOIS_OK = True
except ImportError:
    WHOIS_OK = False

try:
    import ssl
    SSL_OK = True
except ImportError:
    SSL_OK = False

# ── banner ─────────────────────────────────────────────────────────────────────
BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════╗
{Fore.CYAN}║{Fore.MAGENTA}  MIRNOV OSINT ULTIMATE v3.0  {Fore.CYAN}                         ║
{Fore.CYAN}║{Fore.GREEN}  Subdomain · Port · Tech · WAF · WHOIS · SSL · OSINT  {Fore.CYAN}║
{Fore.CYAN}╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""

# ── config ────────────────────────────────────────────────────────────────────
CONFIG = {
    'max_workers':    150,
    'port_timeout':   0.8,
    'http_timeout':   10,
    'google_results': 30,
    'shodan_api':     os.getenv('SHODAN_API_KEY'),
    'tg_token':       os.getenv('TELEGRAM_TOKEN'),
    'tg_chat':        os.getenv('TELEGRAM_CHAT_ID'),
    'output_dir':     'osint_results',
    'follow_redirects': True,
    'verify_ssl':     False,
}

# ── subdomain wordlist ─────────────────────────────────────────────────────────
SUBDOMAINS_BASE = [
    'www','mail','api','admin','dev','test','staging','app','blog','cdn',
    'static','assets','m','mobile','shop','store','forum','support','docs',
    'files','backup','old','vpn','remote','exchange','autodiscover','webmail',
    'cpanel','whm','ftp','ns1','ns2','mx1','mx2','portal','dashboard','beta',
    'demo','intranet','monitor','status','jenkins','git','gitlab','jira',
    'confluence','wiki','ldap','sso','oauth','login','auth','api2','api3',
    'v1','v2','v3','dev-api','test-api','stage-api','admin-api','partner',
    'client','web','secure','my','members','images','video','download',
    'upload','media','help','info','about','news','chat','proxy','mail2',
    'mx','ns','ns3','smtp','pop','imap','vpn2','gateway','firewall','waf',
    'kubernetes','k8s','docker','registry','elasticsearch','kibana','grafana',
    'prometheus','vault','consul','nomad','rancher','harbor','sonar','nexus',
    'artifactory','build','ci','cd','deploy','release','prod','production',
    'uat','qa','sandbox','internal','private','corp','employee','hr','erp',
    'crm','bi','analytics','data','db','database','redis','mongo','mysql',
    'postgres','mssql','oracle','cassandra','kafka','rabbit','nats','etcd',
    's3','storage','assets2','files2','media2','img','pics','attachments',
]

def _expand_subdomains() -> list[str]:
    combos = set(SUBDOMAINS_BASE)
    for sub in SUBDOMAINS_BASE:
        for suf in ['01','02','03','1','2','3','4','5','10','20','99']:
            combos.add(f"{sub}{suf}")
            combos.add(f"{sub}-{suf}")
        for pre in ['test-','dev-','stage-','prod-','new-','old-']:
            combos.add(f"{pre}{sub}")
    return list(combos)

ALL_SUBDOMAINS = _expand_subdomains()

# ── port list ──────────────────────────────────────────────────────────────────
PORTS = [
    20,21,22,23,25,53,69,79,80,88,110,111,119,123,135,137,138,139,143,161,
    179,194,389,443,445,465,500,514,515,587,593,636,666,873,902,993,995,
    1080,1194,1433,1434,1521,1723,1883,2049,2082,2083,2086,2087,2095,2096,
    2181,2375,2376,2379,2380,2424,3000,3306,3389,3690,4000,4369,4443,4505,
    4506,5000,5432,5601,5672,5900,5984,5985,5986,6066,6379,6443,7001,7474,
    7547,8000,8001,8008,8080,8081,8082,8086,8088,8090,8096,8118,8123,8161,
    8200,8333,8443,8500,8686,8787,8880,8888,8983,9000,9001,9042,9090,9092,
    9200,9300,9418,9999,10000,11211,15672,15692,27017,27018,50000,50070,61616,
]

# service map for common ports
SERVICE_MAP = {
    21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',80:'HTTP',
    110:'POP3',143:'IMAP',443:'HTTPS',445:'SMB',3306:'MySQL',
    3389:'RDP',5432:'PostgreSQL',6379:'Redis',8080:'HTTP-Alt',
    8443:'HTTPS-Alt',27017:'MongoDB',9200:'Elasticsearch',
    11211:'Memcached',5900:'VNC',2181:'Zookeeper',4369:'RabbitMQ',
    9092:'Kafka',5672:'AMQP',8888:'Jupyter',9000:'SonarQube',
}

# ── WAF signatures ─────────────────────────────────────────────────────────────
WAF_SIGNATURES = {
    'Cloudflare':   ['cf-ray','cf-cache-status','__cfduid','cf_clearance'],
    'Akamai':       ['akamai','x-akamai-transformed','ak_bmsc','akamaighost'],
    'Imperva':      ['incap_ses','visid_incap','x-iinfo','x-cdn-geo'],
    'AWS WAF':      ['x-amzn-requestid','awswaf','x-amz-cf-id'],
    'ModSecurity':  ['mod_security','modsecurity','x-modsec'],
    'Sucuri':       ['x-sucuri-id','sucuri_cloudproxy','x-sucuri-cache'],
    'F5 BIG-IP':    ['bigipserver','x-wa-info','ts0','tsxxxxxxxx'],
    'Wordfence':    ['wordfence','wfvt_'],
    'Barracuda':    ['barra_counter_session','barracuda'],
    'FortiWeb':     ['fortiweb','fortiwafsid'],
    'Citrix':       ['citrix_ns_id','nf_'],
    'Nginx WAF':    ['x-nginx-cache','ngx_'],
    'Radware':      ['x-sl-compstate','rdwr'],
    'Reblaze':      ['rbzid','x-reblaze'],
    'StackPath':    ['x-sp-url','x-stackpath'],
}

WAF_BYPASSES = {
    'Cloudflare':  ['curl_cffi with real browser TLS','cf_clearance cookie replay','Residential proxy rotation','Puppeteer/Playwright stealth','HTTP/2 with JA3 spoofing'],
    'Akamai':      ['HTTP/2 multiplexing','Delay between requests (>500ms)','Rotate ASN via residential proxies','Mimic real browser TLS fingerprint'],
    'Imperva':     ['Base64 encode params','Random query param padding','POST over GET','Fragment payload across params'],
    'AWS WAF':     ['Rotate IP/region','Use different HTTP methods','X-Forwarded-For header spoofing','Chunked transfer encoding'],
    'ModSecurity': ['Unicode encoding variants','Null byte injection','Comment injection in SQL','HPP (HTTP Parameter Pollution)'],
    'Sucuri':      ['HTTPS with valid SNI','Standard browser UA','Referer from Google','Slow request rate'],
    'F5 BIG-IP':   ['HTTP request smuggling (CL.TE)','X-Forwarded-For spoofing','Double URL encoding','H2C upgrade'],
    'Wordfence':   ['Standard WP headers','Low rate','Remove SQLi signatures from UA'],
    'Cloudflare':  ['Use TLS 1.3','Mimic Chrome JA3','Legitimate ASN'],
}

# ── HTTP session ──────────────────────────────────────────────────────────────
def _session() -> 'requests.Session':
    s = requests.Session()
    s.headers.update({
        'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                       'AppleWebKit/537.36 (KHTML, like Gecko) '
                       'Chrome/124.0.0.0 Safari/537.36'),
        'Accept': 'text/html,application/xhtml+xml,*/*;q=0.9',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
    })
    s.verify = CONFIG['verify_ssl']
    return s

SESSION = _session() if REQ_OK else None

# ─────────────────────────────────────────────────────────────────────────────
# SUBDOMAIN ENUMERATION
# ─────────────────────────────────────────────────────────────────────────────

def _resolve(sub: str, domain: str, ns: list[str] | None = None) -> str | None:
    full = f"{sub}.{domain}"
    try:
        if DNS_OK:
            res = dns.resolver.Resolver()
            if ns:
                res.nameservers = ns
            res.lifetime = 2.0
            res.resolve(full, 'A')
        else:
            socket.gethostbyname(full)
        return full
    except Exception:
        return None

def find_subdomains_bruteforce(domain: str,
                                ns: list[str] | None = None) -> list[str]:
    print(f"{Fore.CYAN}[*] Brute-force subdomain enum: {domain}{Style.RESET_ALL}")
    found: list[str] = []
    with ThreadPoolExecutor(max_workers=CONFIG['max_workers']) as ex:
        futs = {ex.submit(_resolve, sub, domain, ns): sub
                for sub in ALL_SUBDOMAINS}
        for f in tqdm(as_completed(futs), total=len(futs), desc="DNS-BF"):
            result = f.result()
            if result:
                found.append(result)
                print(f"{Fore.GREEN}  [+] {result}{Style.RESET_ALL}")
    return found

def find_subdomains_crtsh(domain: str) -> list[str]:
    if not REQ_OK:
        return []
    print(f"{Fore.CYAN}[*] crt.sh certificate transparency: {domain}{Style.RESET_ALL}")
    subs: set[str] = set()
    try:
        r = SESSION.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=30
        )
        if r.ok:
            for entry in r.json():
                for name in entry.get('name_value', '').splitlines():
                    name = name.strip().lstrip('*.')
                    if name.endswith(domain) and name != domain:
                        subs.add(name)
    except Exception as e:
        print(f"{Fore.YELLOW}  [!] crt.sh error: {e}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}  [+] crt.sh found {len(subs)} subdomains{Style.RESET_ALL}")
    return list(subs)

def find_subdomains_threatcrowd(domain: str) -> list[str]:
    if not REQ_OK:
        return []
    print(f"{Fore.CYAN}[*] ThreatCrowd: {domain}{Style.RESET_ALL}")
    try:
        r = SESSION.get(
            f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}",
            timeout=15
        )
        if r.ok:
            data = r.json()
            subs = data.get('subdomains', [])
            print(f"{Fore.GREEN}  [+] ThreatCrowd: {len(subs)}{Style.RESET_ALL}")
            return [s for s in subs if isinstance(s, str)]
    except Exception:
        pass
    return []

def find_subdomains_hackertarget(domain: str) -> list[str]:
    if not REQ_OK:
        return []
    print(f"{Fore.CYAN}[*] HackerTarget: {domain}{Style.RESET_ALL}")
    try:
        r = SESSION.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=15
        )
        if r.ok and 'error' not in r.text.lower():
            subs = []
            for line in r.text.splitlines():
                parts = line.split(',')
                if parts:
                    sub = parts[0].strip()
                    if sub.endswith(domain):
                        subs.append(sub)
            print(f"{Fore.GREEN}  [+] HackerTarget: {len(subs)}{Style.RESET_ALL}")
            return subs
    except Exception:
        pass
    return []

def find_subdomains_alienvault(domain: str) -> list[str]:
    if not REQ_OK:
        return []
    print(f"{Fore.CYAN}[*] AlienVault OTX: {domain}{Style.RESET_ALL}")
    subs: set[str] = set()
    page = 1
    while page <= 5:
        try:
            r = SESSION.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
                params={"page": page, "limit": 100},
                timeout=15
            )
            if not r.ok:
                break
            data = r.json()
            records = data.get('passive_dns', [])
            if not records:
                break
            for rec in records:
                hostname = rec.get('hostname', '')
                if hostname.endswith(domain):
                    subs.add(hostname)
            page += 1
        except Exception:
            break
    print(f"{Fore.GREEN}  [+] AlienVault: {len(subs)}{Style.RESET_ALL}")
    return list(subs)

def find_all_subdomains(domain: str,
                         ns: list[str] | None = None) -> list[str]:
    all_subs: set[str] = set()
    for fn in [
        lambda: find_subdomains_bruteforce(domain, ns),
        lambda: find_subdomains_crtsh(domain),
        lambda: find_subdomains_threatcrowd(domain),
        lambda: find_subdomains_hackertarget(domain),
        lambda: find_subdomains_alienvault(domain),
    ]:
        try:
            all_subs.update(fn())
        except Exception as e:
            print(f"{Fore.YELLOW}  [!] source error: {e}{Style.RESET_ALL}")
    return sorted(all_subs)

# ─────────────────────────────────────────────────────────────────────────────
# DNS RECORDS
# ─────────────────────────────────────────────────────────────────────────────

def get_dns_records(domain: str) -> dict:
    if not DNS_OK:
        return {}
    print(f"{Fore.CYAN}[*] DNS records: {domain}{Style.RESET_ALL}")
    records: dict[str, list[str]] = {}
    for rtype in ['A','AAAA','CNAME','MX','NS','TXT','SOA','CAA','SRV','PTR']:
        try:
            ans = dns.resolver.resolve(domain, rtype, lifetime=5)
            records[rtype] = [str(r) for r in ans]
        except Exception:
            pass
    return records

def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""

# ─────────────────────────────────────────────────────────────────────────────
# PORT SCANNING
# ─────────────────────────────────────────────────────────────────────────────

def scan_port(ip: str, port: int) -> int | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(CONFIG['port_timeout'])
            if s.connect_ex((ip, port)) == 0:
                return port
    except Exception:
        pass
    return None

def get_banner(ip: str, port: int, timeout: float = 3.0) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            if port in {80,8080,8000,8008,8081,8082,8088,8090}:
                s.send(b"HEAD / HTTP/1.0\r\nHost: " +
                       ip.encode() + b"\r\n\r\n")
            elif port in {443,8443,4443}:
                # skip raw banner on TLS ports
                return "(TLS — see SSL info)"
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner[:300]
    except Exception:
        return ""

def scan_ports(ip: str) -> tuple[list[int], dict[int, str]]:
    print(f"{Fore.CYAN}[*] Port scan: {ip} ({len(PORTS)} ports){Style.RESET_ALL}")
    open_ports: list[int] = []
    banners:    dict[int, str] = {}

    with ThreadPoolExecutor(max_workers=CONFIG['max_workers']) as ex:
        futs = {ex.submit(scan_port, ip, p): p for p in PORTS}
        for f in tqdm(as_completed(futs), total=len(futs), desc="Ports"):
            port = futs[f]
            if f.result() is not None:
                open_ports.append(port)
                banner = get_banner(ip, port)
                banners[port] = banner
                svc = SERVICE_MAP.get(port, 'unknown')
                print(f"{Fore.GREEN}  [+] {port}/{svc} "
                      f"— {banner[:60] or 'no banner'}{Style.RESET_ALL}")

    return sorted(open_ports), banners

# ─────────────────────────────────────────────────────────────────────────────
# TECHNOLOGY DETECTION
# ─────────────────────────────────────────────────────────────────────────────

CMS_SIGS: dict[str, str] = {
    'WordPress':  'wp-content',
    'Joomla':     '/components/com_',
    'Drupal':     '/sites/default/files',
    'Magento':    'mage/',
    'Shopify':    'cdn.shopify.com',
    'Laravel':    'laravel_session',
    'Django':     'csrftoken',
    'Rails':      '_rails_session',
    'ASP.NET':    '__VIEWSTATE',
    'React':      'react-root',
    'Angular':    'ng-version',
    'Vue.js':     'vue-app',
    'Next.js':    '__NEXT_DATA__',
    'Nuxt.js':    '__nuxt',
    'jQuery':     'jquery',
    'Bootstrap':  'bootstrap',
    'Tailwind':   'tailwind',
    'Webpack':    'webpack',
    'Vite':       '/@vite/',
    'Svelte':     '__svelte',
    'Gatsby':     'gatsby-',
    'Hugo':       'hugo-',
    'Ghost':      'ghost/',
}

HEADER_SIGS: list[tuple[str, str]] = [
    ('Server',        'server'),
    ('X-Powered-By',  'powered'),
    ('X-Generator',   'generator'),
    ('X-CMS',         'cms'),
    ('X-Drupal-Cache','drupal'),
    ('X-Varnish',     'varnish'),
    ('Via',           'via'),
    ('X-Cache',       'cache'),
]

def detect_technologies(url: str) -> dict:
    if not REQ_OK:
        return {}
    print(f"{Fore.CYAN}[*] Technology fingerprint: {url}{Style.RESET_ALL}")
    result: dict[str, list[str]] = {
        'headers': [], 'cms': [], 'js_frameworks': [],
        'security_headers': [], 'cookies': [],
    }
    try:
        r = SESSION.get(url, timeout=CONFIG['http_timeout'],
                        allow_redirects=CONFIG['follow_redirects'])
        headers = r.headers
        html    = r.text.lower()

        # response headers
        for hdr, _ in HEADER_SIGS:
            if hdr in headers:
                result['headers'].append(f"{hdr}: {headers[hdr]}")

        # CMS/framework detection
        for name, sig in CMS_SIGS.items():
            if sig.lower() in html:
                result['cms'].append(name)

        # security headers audit
        sec_hdrs = ['Strict-Transport-Security','Content-Security-Policy',
                    'X-Frame-Options','X-Content-Type-Options',
                    'Referrer-Policy','Permissions-Policy']
        for hdr in sec_hdrs:
            if hdr in headers:
                result['security_headers'].append(f"{hdr}: {headers[hdr][:80]}")
            else:
                result['security_headers'].append(f"MISSING: {hdr}")

        # cookies
        for cookie in r.cookies:
            flags = []
            if cookie.secure:    flags.append('Secure')
            if cookie.has_nonstandard_attr('HttpOnly'): flags.append('HttpOnly')
            result['cookies'].append(
                f"{cookie.name} ({', '.join(flags) or 'no flags'})"
            )

        # status + redirect chain
        result['status_code']    = r.status_code
        result['redirect_chain'] = [resp.url for resp in r.history]

    except Exception as e:
        result['error'] = str(e)

    return result

# ─────────────────────────────────────────────────────────────────────────────
# WAF DETECTION
# ─────────────────────────────────────────────────────────────────────────────

def detect_waf(url: str) -> str:
    if not REQ_OK:
        return "requests not available"
    print(f"{Fore.CYAN}[*] WAF detection: {url}{Style.RESET_ALL}")
    try:
        # probe with a benign SQLi pattern to trigger WAF
        probe_url = url + "/?id=1'+OR+'1'='1"
        r = SESSION.get(probe_url, timeout=CONFIG['http_timeout'])
        haystack = (str(r.headers) + str(r.cookies) + r.text[:2000]).lower()

        for waf_name, sigs in WAF_SIGNATURES.items():
            for sig in sigs:
                if sig.lower() in haystack:
                    print(f"{Fore.YELLOW}  [!] WAF: {waf_name}{Style.RESET_ALL}")
                    return waf_name

        # block detection by status code
        if r.status_code in (403, 406, 429, 503):
            return f"WAF/Rate-limit (HTTP {r.status_code})"

        return "No WAF detected"
    except Exception as e:
        return f"WAF check error: {e}"

# ─────────────────────────────────────────────────────────────────────────────
# SSL/TLS ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────

def get_ssl_info(domain: str, port: int = 443) -> dict:
    if not SSL_OK:
        return {}
    print(f"{Fore.CYAN}[*] SSL/TLS: {domain}:{port}{Style.RESET_ALL}")
    info: dict = {}
    try:
        import ssl, socket
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with ctx.wrap_socket(
            socket.create_connection((domain, port), timeout=8),
            server_hostname=domain
        ) as conn:
            cert = conn.getpeercert()
            info['version']     = conn.version()
            info['cipher']      = conn.cipher()
            info['subject']     = dict(x[0] for x in cert.get('subject', []))
            info['issuer']      = dict(x[0] for x in cert.get('issuer', []))
            info['not_before']  = cert.get('notBefore', '')
            info['not_after']   = cert.get('notAfter', '')
            info['san']         = [
                v for _, v in cert.get('subjectAltName', [])
            ]
            # check expiry
            from datetime import datetime
            exp = datetime.strptime(info['not_after'], '%b %d %H:%M:%S %Y %Z')
            days_left = (exp - datetime.utcnow()).days
            info['days_until_expiry'] = days_left
            if days_left < 30:
                info['warning'] = f"Certificate expires in {days_left} days!"
    except Exception as e:
        info['error'] = str(e)
    return info

# ─────────────────────────────────────────────────────────────────────────────
# WHOIS
# ─────────────────────────────────────────────────────────────────────────────

def get_whois(domain: str) -> dict:
    if not WHOIS_OK:
        return {"error": "pip install python-whois"}
    print(f"{Fore.CYAN}[*] WHOIS: {domain}{Style.RESET_ALL}")
    try:
        w = _whois.whois(domain)
        return {
            'registrar':    str(w.registrar or ''),
            'creation_date':str(w.creation_date or ''),
            'expiration_date': str(w.expiration_date or ''),
            'updated_date': str(w.updated_date or ''),
            'name_servers': list(w.name_servers or []),
            'status':       list(w.status or [])
                            if isinstance(w.status, list)
                            else [str(w.status or '')],
            'emails':       list(w.emails or [])
                            if isinstance(w.emails, list)
                            else [str(w.emails or '')],
            'org':          str(w.org or ''),
            'country':      str(w.country or ''),
        }
    except Exception as e:
        return {'error': str(e)}

# ─────────────────────────────────────────────────────────────────────────────
# GOOGLE DORKS
# ─────────────────────────────────────────────────────────────────────────────

def generate_dorks(domain: str) -> list[str]:
    return [
        f"site:{domain}",
        f"site:{domain} inurl:admin",
        f"site:{domain} inurl:login",
        f"site:{domain} inurl:dashboard",
        f"site:{domain} inurl:panel",
        f"site:{domain} filetype:log",
        f"site:{domain} filetype:sql",
        f"site:{domain} filetype:conf",
        f"site:{domain} filetype:bak",
        f"site:{domain} filetype:old",
        f"site:{domain} intitle:index.of",
        f"site:{domain} intitle:phpinfo",
        f"site:{domain} intitle:\"Directory listing\"",
        f"site:{domain} inurl:.env",
        f"site:{domain} inurl:/backup",
        f"site:{domain} inurl:aws",
        f"site:{domain} inurl:s3",
        f"site:{domain} inurl:swagger",
        f"site:{domain} inurl:api-docs",
        f"site:{domain} inurl:graphql",
        f"site:{domain} inurl:jenkins",
        f"site:{domain} inurl:grafana",
        f"site:{domain} inurl:kibana",
        f"site:{domain} inurl:gitlab",
        f"site:{domain} inurl:jira",
        f"site:{domain} inurl:confluence",
        f"site:{domain} intext:password",
        f"site:{domain} intext:api_key",
        f"site:{domain} intext:secret_key",
        f"site:{domain} intext:\"access_token\"",
        f"site:{domain} inurl:wp-admin",
        f"site:{domain} inurl:phpmyadmin",
        f"site:{domain} inurl:elasticsearch",
        f"site:{domain} inurl:actuator",
        f"site:{domain} inurl:.git",
        f"site:{domain} ext:txt ext:csv ext:json ext:xml",
        f"cache:{domain}",
        f"related:{domain}",
        f"\"{domain}\" password filetype:txt",
        f"\"{domain}\" \"db_password\" ext:env",
    ]

def run_google_dorks(domain: str) -> list[str]:
    if not GOOGLE_OK:
        print(f"{Fore.YELLOW}[!] pip install googlesearch-python{Style.RESET_ALL}")
        return []
    print(f"{Fore.CYAN}[*] Google dorking: {domain}{Style.RESET_ALL}")
    results: set[str] = set()
    dorks = generate_dorks(domain)[:15]
    for dork in tqdm(dorks, desc="Dorks"):
        try:
            for url in google_search(dork,
                                     num_results=CONFIG['google_results'],
                                     sleep_interval=2):
                results.add(url)
        except Exception:
            time.sleep(5)
    return sorted(results)

# ─────────────────────────────────────────────────────────────────────────────
# SHODAN
# ─────────────────────────────────────────────────────────────────────────────

def shodan_lookup(ip: str, api_key: str | None = None) -> dict:
    key = api_key or CONFIG.get('shodan_api')
    if not key or not REQ_OK:
        return {}
    print(f"{Fore.CYAN}[*] Shodan: {ip}{Style.RESET_ALL}")
    try:
        r = SESSION.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": key},
            timeout=CONFIG['http_timeout']
        )
        if r.ok:
            d = r.json()
            return {
                'org':       d.get('org', ''),
                'isp':       d.get('isp', ''),
                'asn':       d.get('asn', ''),
                'country':   d.get('country_name', ''),
                'city':      d.get('city', ''),
                'ports':     d.get('ports', []),
                'vulns':     list(d.get('vulns', {}).keys()),
                'hostnames': d.get('hostnames', []),
                'tags':      d.get('tags', []),
                'os':        d.get('os', ''),
                'last_update': d.get('last_update', ''),
            }
    except Exception as e:
        return {'error': str(e)}
    return {}

# ─────────────────────────────────────────────────────────────────────────────
# HONEYPOT DETECTION
# ─────────────────────────────────────────────────────────────────────────────

def detect_honeypot(url: str) -> dict:
    if not REQ_OK:
        return {}
    print(f"{Fore.CYAN}[*] Honeypot detection: {url}{Style.RESET_ALL}")
    signals: list[str] = []
    verdict = "likely_clean"
    try:
        r = SESSION.get(url, timeout=CONFIG['http_timeout'])
        hdrs = str(r.headers).lower()
        body = r.text.lower()

        hp_keywords = ['honeypot','canary','decoy','trap','honeynet',
                       'kippo','cowrie','glastopf','dionaea']
        for kw in hp_keywords:
            if kw in body or kw in hdrs:
                signals.append(f"keyword:{kw}")

        # suspicious 200 on random nonexistent paths
        fake_path = f"/nonexistent_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
        r2 = SESSION.get(url.rstrip('/') + fake_path,
                         timeout=CONFIG['http_timeout'])
        if r2.status_code == 200 and len(r2.content) > 100:
            signals.append("200_on_nonexistent_path")

        # response too consistent
        r3 = SESSION.get(url.rstrip('/') + "/admin/../admin",
                         timeout=CONFIG['http_timeout'])
        if r3.status_code == r2.status_code and r3.text == r2.text:
            signals.append("identical_responses_to_different_paths")

        # too fast responses (real servers have variable latency)
        times = []
        for _ in range(3):
            t0 = time.time()
            SESSION.get(url, timeout=CONFIG['http_timeout'])
            times.append(time.time() - t0)
        variance = max(times) - min(times)
        if variance < 0.01:
            signals.append(f"suspiciously_uniform_latency:{variance:.4f}s")

        if len(signals) >= 2:
            verdict = "likely_honeypot"
        elif signals:
            verdict = "suspicious"

    except Exception as e:
        return {'verdict': 'error', 'error': str(e)}

    return {'verdict': verdict, 'signals': signals}

# ─────────────────────────────────────────────────────────────────────────────
# IP REPUTATION
# ─────────────────────────────────────────────────────────────────────────────

def check_ip_reputation(ip: str) -> dict:
    if not REQ_OK:
        return {}
    print(f"{Fore.CYAN}[*] IP reputation: {ip}{Style.RESET_ALL}")
    result: dict = {}

    # AbuseIPDB
    abuse_key = os.getenv('ABUSEIPDB_KEY', '')
    if abuse_key:
        try:
            r = SESSION.get(
                'https://api.abuseipdb.com/api/v2/check',
                headers={'Key': abuse_key, 'Accept': 'application/json'},
                params={'ipAddress': ip, 'maxAgeInDays': 90},
                timeout=8
            )
            if r.ok:
                d = r.json().get('data', {})
                result['abuseipdb'] = {
                    'score':    d.get('abuseConfidenceScore', 0),
                    'reports':  d.get('totalReports', 0),
                    'country':  d.get('countryCode', ''),
                    'isp':      d.get('isp', ''),
                    'is_tor':   d.get('isTor', False),
                }
        except Exception as e:
            result['abuseipdb_error'] = str(e)

    # VirusTotal
    vt_key = os.getenv('VT_KEY', '')
    if vt_key:
        try:
            r = SESSION.get(
                f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
                headers={'x-apikey': vt_key},
                timeout=8
            )
            if r.ok:
                attrs  = r.json().get('data', {}).get('attributes', {})
                stats  = attrs.get('last_analysis_stats', {})
                result['virustotal'] = {
                    'malicious':  stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'harmless':   stats.get('harmless', 0),
                    'country':    attrs.get('country', ''),
                    'asn':        attrs.get('asn', ''),
                    'org':        attrs.get('as_owner', ''),
                }
        except Exception as e:
            result['virustotal_error'] = str(e)

    return result

# ─────────────────────────────────────────────────────────────────────────────
# EMAIL SECURITY (SPF / DKIM / DMARC)
# ─────────────────────────────────────────────────────────────────────────────

def check_email_security(domain: str) -> dict:
    if not DNS_OK:
        return {}
    print(f"{Fore.CYAN}[*] Email security (SPF/DKIM/DMARC): {domain}{Style.RESET_ALL}")
    result: dict = {}

    # SPF
    try:
        ans = dns.resolver.resolve(domain, 'TXT', lifetime=5)
        for r in ans:
            txt = str(r)
            if 'v=spf1' in txt:
                result['spf'] = txt
                break
        else:
            result['spf'] = 'MISSING'
    except Exception:
        result['spf'] = 'ERROR'

    # DMARC
    try:
        ans = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT', lifetime=5)
        for r in ans:
            txt = str(r)
            if 'v=DMARC1' in txt:
                result['dmarc'] = txt
                break
        else:
            result['dmarc'] = 'MISSING'
    except Exception:
        result['dmarc'] = 'MISSING'

    # DKIM (common selectors)
    dkim_found = []
    for selector in ['default','google','k1','mail','dkim','s1','s2',
                     'selector1','selector2','email']:
        try:
            dns.resolver.resolve(
                f'{selector}._domainkey.{domain}', 'TXT', lifetime=3
            )
            dkim_found.append(selector)
        except Exception:
            pass
    result['dkim_selectors_found'] = dkim_found

    return result

# ─────────────────────────────────────────────────────────────────────────────
# REPORT GENERATION
# ─────────────────────────────────────────────────────────────────────────────

def build_report(data: dict) -> str:
    d = data
    sep = "═" * 62
    lines = [
        BANNER,
        f"MIRNOV OSINT v3.0 — {d['domain']}",
        f"IP: {d.get('ip','?')}  |  Date: {datetime.now():%Y-%m-%d %H:%M:%S}",
        sep,
        f"\n[SUBDOMAINS] {len(d.get('subdomains',[]))} found",
    ]
    for s in d.get('subdomains', []):
        lines.append(f"  {s}")

    lines.append(f"\n[DNS RECORDS]")
    for rtype, vals in d.get('dns_records', {}).items():
        lines.append(f"  {rtype}: {', '.join(vals)}")

    lines.append(f"\n[OPEN PORTS] {len(d.get('open_ports',[]))} open")
    for p in d.get('open_ports', []):
        svc    = SERVICE_MAP.get(p, 'unknown')
        banner = d.get('banners', {}).get(p, '')
        lines.append(f"  {p}/{svc}  {banner[:80]}")

    lines.append(f"\n[TECHNOLOGIES]")
    tech = d.get('tech', {})
    for cat, items in tech.items():
        if items and cat != 'error':
            if isinstance(items, list):
                for item in items:
                    lines.append(f"  [{cat}] {item}")
            else:
                lines.append(f"  [{cat}] {items}")

    lines.append(f"\n[WAF] {d.get('waf','?')}")
    lines.append(f"\n[WAF BYPASS METHODS]")
    for m in d.get('waf_bypass', []):
        lines.append(f"  - {m}")

    lines.append(f"\n[SSL/TLS]")
    for k, v in d.get('ssl', {}).items():
        lines.append(f"  {k}: {v}")

    lines.append(f"\n[WHOIS]")
    for k, v in d.get('whois', {}).items():
        lines.append(f"  {k}: {v}")

    lines.append(f"\n[EMAIL SECURITY]")
    for k, v in d.get('email_security', {}).items():
        lines.append(f"  {k}: {v}")

    lines.append(f"\n[HONEYPOT DETECTION]")
    hp = d.get('honeypot', {})
    lines.append(f"  verdict: {hp.get('verdict','?')}")
    for sig in hp.get('signals', []):
        lines.append(f"  signal: {sig}")

    lines.append(f"\n[IP REPUTATION]")
    for provider, info in d.get('reputation', {}).items():
        if isinstance(info, dict):
            for k, v in info.items():
                lines.append(f"  [{provider}] {k}: {v}")

    lines.append(f"\n[SHODAN]")
    for k, v in d.get('shodan', {}).items():
        lines.append(f"  {k}: {v}")

    lines.append(f"\n[GOOGLE DORKS] {len(d.get('dorks',[]))} generated")
    for dk in d.get('dorks', [])[:20]:
        lines.append(f"  {dk}")

    lines.append(f"\n[GOOGLE RESULTS] {len(d.get('google_results',[]))} URLs")
    for url in d.get('google_results', [])[:30]:
        lines.append(f"  {url}")

    lines.append(f"\n{sep}")
    lines.append("Report by Mirnov OSINT v3.0 — usellts")
    return "\n".join(lines)

def save_reports(base: str, data: dict, report_txt: str):
    Path(CONFIG['output_dir']).mkdir(exist_ok=True)
    base_path = Path(CONFIG['output_dir']) / base

    # TXT
    (base_path.parent / (base + '.txt')).write_text(report_txt, encoding='utf-8')

    # JSON
    with open(str(base_path) + '.json', 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)

    # HTML
    html = (
        "<!DOCTYPE html><html><head>"
        "<meta charset='utf-8'>"
        "<title>Mirnov OSINT Report</title>"
        "<style>body{background:#0d1117;color:#e6edf3;"
        "font-family:monospace;padding:20px}"
        "pre{white-space:pre-wrap;word-break:break-all}"
        ".green{color:#3fb950}.yellow{color:#d29922}"
        ".red{color:#f85149}.blue{color:#58a6ff}"
        "</style></head><body><pre>"
        + report_txt.replace('<', '&lt;').replace('>', '&gt;')
        + "</pre></body></html>"
    )
    with open(str(base_path) + '.html', 'w', encoding='utf-8') as f:
        f.write(html)

    # PDF
    if PDF_OK:
        try:
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Courier", size=9)
            for line in report_txt.split('\n'):
                pdf.cell(0, 4,
                         txt=line[:195].encode('latin-1',
                                               errors='replace').decode('latin-1'),
                         ln=True)
            pdf.output(str(base_path) + '.pdf')
            print(f"{Fore.GREEN}[+] PDF: {base_path}.pdf{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}[!] PDF: {e}{Style.RESET_ALL}")

    print(f"{Fore.GREEN}[+] Reports → {CONFIG['output_dir']}/{base}.[txt|json|html]{Style.RESET_ALL}")

# ─────────────────────────────────────────────────────────────────────────────
# TELEGRAM
# ─────────────────────────────────────────────────────────────────────────────

def send_telegram(msg: str) -> bool:
    token   = CONFIG.get('tg_token')
    chat_id = CONFIG.get('tg_chat')
    if not token or not chat_id or not REQ_OK:
        return False
    try:
        r = SESSION.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id,
                  "text": msg[:4096],
                  "parse_mode": "HTML"},
            timeout=10
        )
        return r.ok
    except Exception:
        return False

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print(BANNER)

    target = input(
        f"{Fore.CYAN}[>] Target (domain or URL): {Style.RESET_ALL}"
    ).strip()
    if not target:
        print(f"{Fore.RED}[!] No target{Style.RESET_ALL}")
        sys.exit(1)

    domain = urlparse(target).netloc if target.startswith('http') else target
    domain = domain.lower().strip('/')
    url    = f"https://{domain}"

    print(f"{Fore.YELLOW}[*] Target: {domain}{Style.RESET_ALL}\n")

    # resolve IP
    ip: str | None = None
    try:
        ip = socket.gethostbyname(domain)
        rdns = reverse_dns(ip)
        print(f"{Fore.GREEN}[+] IP: {ip}  rDNS: {rdns or '—'}{Style.RESET_ALL}")
    except Exception:
        print(f"{Fore.RED}[!] Could not resolve {domain}{Style.RESET_ALL}")

    # run all modules
    subdomains   = find_all_subdomains(domain)
    dns_records  = get_dns_records(domain)
    open_ports, banners = scan_ports(ip) if ip else ([], {})
    tech         = detect_technologies(url)
    waf          = detect_waf(url)
    waf_bypass   = WAF_BYPASSES.get(waf, ['Rotate IP','Change User-Agent'])
    ssl_info     = get_ssl_info(domain)
    whois_info   = get_whois(domain)
    email_sec    = check_email_security(domain)
    honeypot     = detect_honeypot(url)
    reputation   = check_ip_reputation(ip) if ip else {}
    shodan       = shodan_lookup(ip) if ip else {}
    dorks        = generate_dorks(domain)
    google       = run_google_dorks(domain)

    # bundle data
    data = {
        'domain':         domain,
        'ip':             ip,
        'rdns':           reverse_dns(ip) if ip else '',
        'subdomains':     subdomains,
        'dns_records':    dns_records,
        'open_ports':     open_ports,
        'banners':        {str(k): v for k, v in banners.items()},
        'tech':           tech,
        'waf':            waf,
        'waf_bypass':     waf_bypass,
        'ssl':            ssl_info,
        'whois':          whois_info,
        'email_security': email_sec,
        'honeypot':       honeypot,
        'reputation':     reputation,
        'shodan':         shodan,
        'dorks':          dorks,
        'google_results': google,
        'timestamp':      datetime.now().isoformat(),
    }

    report = build_report(data)
    print(report)

    base = f"mirnov_{domain}_{datetime.now():%Y%m%d_%H%M%S}"
    save_reports(base, data, report)

    # Telegram summary
    if CONFIG.get('tg_token') and CONFIG.get('tg_chat'):
        summary = (
            f"<b>🔍 Mirnov OSINT v3.0</b>\n"
            f"Target: <code>{domain}</code>\n"
            f"IP: <code>{ip}</code>\n"
            f"Subdomains: {len(subdomains)}\n"
            f"Open ports: {len(open_ports)}\n"
            f"WAF: {waf}\n"
            f"Honeypot: {honeypot.get('verdict','?')}\n"
            f"Vulns (Shodan): {', '.join(shodan.get('vulns',[]) or ['none'])}"
        )
        send_telegram(summary)
        print(f"{Fore.GREEN}[+] Telegram notified{Style.RESET_ALL}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Interrupted{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Fatal: {e}{Style.RESET_ALL}")
        raise