from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import socket
import ssl
import requests
import threading
import time
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from bs4 import BeautifulSoup
import configparser
from urllib.parse import urlparse, parse_qs
import os
import dns.resolver
import dns.reversename
import re
import hashlib
import json
from collections import defaultdict

app = Flask(__name__)
CORS(app)

# Configuration
VERSION = '1.0.5'

def is_using_cloudflare(domain):
    try:
        response = requests.head(f"https://{domain}", timeout=5)
        headers = response.headers
        if "server" in headers and "cloudflare" in headers["server"].lower():
            return True
        if "cf-ray" in headers:
            return True
        if "cloudflare" in headers:
            return True
    except (requests.exceptions.RequestException, requests.exceptions.ConnectionError):
        pass
    return False

def detect_web_server(domain):
    try:
        response = requests.head(f"https://{domain}", timeout=5)
        server_header = response.headers.get("Server")
        if server_header:
            return server_header.strip()
    except (requests.exceptions.RequestException, requests.exceptions.ConnectionError):
        pass
    return "UNKNOWN"

def get_ssl_certificate_info(host):
    try:
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(), server_hostname=host) as sock:
            sock.connect((host, 443))
            certificate_der = sock.getpeercert(True)
            certificate = x509.load_der_x509_certificate(certificate_der, default_backend())
            
            common_name = certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            issuer = certificate.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            validity_start = certificate.not_valid_before_utc
            validity_end = certificate.not_valid_after_utc
            
            return {
                "Common Name": str(common_name),
                "Issuer": str(issuer),
                "Validity Start": str(validity_start),
                "Validity End": str(validity_end),
            }
    except Exception as e:
        return None

def get_real_ip(host):
    try:
        real_ip = socket.gethostbyname(host)
        return real_ip
    except socket.gaierror:
        return None

def get_domain_historical_ip_address(domain):
    try:
        url = f"https://viewdns.info/iphistory/?domain={domain}"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        }
        response = requests.get(url, headers=headers, timeout=10)
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')
        table = soup.find('table', {'border': '1'})
        
        historical_ips = []
        if table:
            rows = table.find_all('tr')[2:]
            for row in rows:
                columns = row.find_all('td')
                if len(columns) >= 4:
                    ip_address = columns[0].text.strip()
                    location = columns[1].text.strip()
                    owner = columns[2].text.strip()
                    last_seen = columns[3].text.strip()
                    historical_ips.append({
                        "ip": ip_address,
                        "location": location,
                        "owner": owner,
                        "last_seen": last_seen
                    })
        return historical_ips
    except Exception as e:
        return []

def find_subdomains_with_ssl_analysis(domain, wordlist_path="wordlist.txt", timeout=10):
    subdomains_found = []
    subdomains_lock = threading.Lock()
    
    def check_subdomain(subdomain):
        subdomain_url = f"https://{subdomain}.{domain}"
        try:
            response = requests.get(subdomain_url, timeout=timeout)
            if response.status_code == 200:
                with subdomains_lock:
                    subdomains_found.append(subdomain_url)
        except requests.exceptions.RequestException:
            pass
    
    if not os.path.exists(wordlist_path):
        wordlist_path = "wordlist.txt"
    
    try:
        with open(wordlist_path, "r") as file:
            subdomains = [line.strip() for line in file.readlines()]
    except:
        return []
    
    threads = []
    for subdomain in subdomains:
        thread = threading.Thread(target=check_subdomain, args=(subdomain,))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    real_ips = []
    for subdomain in subdomains_found:
        subdomain_parts = subdomain.split('//')
        if len(subdomain_parts) > 1:
            host = subdomain_parts[1]
            real_ip = get_real_ip(host)
            if real_ip:
                ssl_info = get_ssl_certificate_info(host)
                real_ips.append({
                    "host": host,
                    "ip": real_ip,
                    "ssl_info": ssl_info
                })
    
    return {
        "total_scanned": len(subdomains),
        "total_found": len(subdomains_found),
        "results": real_ips
    }

# ========== NEW RECON FUNCTIONS ==========

def get_dns_records(domain):
    """Enumerate DNS records (A, AAAA, MX, NS, TXT, SOA, CNAME)"""
    dns_data = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
    
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            dns_data[record_type] = [str(rdata) for rdata in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            dns_data[record_type] = []
        except Exception:
            dns_data[record_type] = []
    
    return dns_data

def get_whois_info(domain):
    """Get WHOIS information for domain"""
    try:
        import whois
        whois_data = whois.whois(domain)
        return {
            "registrar": str(whois_data.registrar),
            "created": str(whois_data.creation_date),
            "expires": str(whois_data.expiration_date),
            "updated": str(whois_data.updated_date),
            "nameservers": whois_data.nameservers if whois_data.nameservers else [],
            "status": whois_data.status if whois_data.status else []
        }
    except Exception as e:
        return {"error": str(e)}

def scan_common_ports(host, ports=None):
    """Scan common ports on target"""
    if ports is None:
        ports = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 5900, 8080, 8443, 9000]
    
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                    open_ports.append({"port": port, "service": service})
                except:
                    open_ports.append({"port": port, "service": "unknown"})
            sock.close()
        except:
            pass
    
    return open_ports

def detect_technologies(domain):
    """Detect CMS, frameworks, and technologies"""
    technologies = []
    
    try:
        response = requests.get(f"https://{domain}", timeout=5, allow_redirects=True)
        html = response.text
        headers = response.headers
        
        # Check for common CMS/Framework patterns
        patterns = {
            'WordPress': [r'wp-content', r'wp-includes', r'/wp-admin/', r'WordPress'],
            'Drupal': [r'sites/default', r'/modules/', r'/themes/', r'Drupal'],
            'Joomla': [r'/components/', r'/administrator/', r'Joomla'],
            'Magento': [r'/skin/', r'/media/', r'Magento'],
            'Django': [r'csrfmiddlewaretoken', r'django'],
            'React': [r'__REACT_', r'react'],
            'Vue.js': [r'__vue__', r'Vue'],
            'Angular': [r'ng-app', r'angular'],
        }
        
        for tech, pattern_list in patterns.items():
            for pattern in pattern_list:
                if re.search(pattern, html, re.IGNORECASE):
                    technologies.append(tech)
                    break
        
        # Check headers for server/framework info
        if 'X-Powered-By' in headers:
            technologies.append(headers['X-Powered-By'])
        if 'Server' in headers:
            technologies.append(headers['Server'])
        
    except:
        pass
    
    return list(set(technologies))

def analyze_security_headers(domain):
    """Analyze HTTP security headers"""
    security_headers = {}
    
    try:
        response = requests.get(f"https://{domain}", timeout=5, allow_redirects=True)
        headers = response.headers
        
        security_headers_to_check = {
            'Strict-Transport-Security': 'HSTS',
            'Content-Security-Policy': 'CSP',
            'X-Content-Type-Options': 'X-Content-Type',
            'X-Frame-Options': 'X-Frame',
            'X-XSS-Protection': 'X-XSS',
            'Referrer-Policy': 'Referrer',
            'Permissions-Policy': 'Permissions',
            'Access-Control-Allow-Origin': 'CORS'
        }
        
        for header, name in security_headers_to_check.items():
            if header in headers:
                security_headers[name] = headers[header]
            else:
                security_headers[name] = "NOT SET"
    
    except:
        pass
    
    return security_headers

def enumerate_emails(domain):
    """Extract emails from DNS and common patterns"""
    emails = []
    
    try:
        # Check DNS TXT records for emails
        dns_records = get_dns_records(domain)
        
        # Search in TXT records
        for txt_record in dns_records.get('TXT', []):
            emails_found = re.findall(r'[\w\.-]+@' + re.escape(domain), txt_record)
            emails.extend(emails_found)
        
        # Common email patterns
        response = requests.get(f"https://{domain}", timeout=5, allow_redirects=True)
        html = response.text
        found_emails = re.findall(r'[\w\.-]+@' + re.escape(domain), html)
        emails.extend(found_emails)
    
    except:
        pass
    
    return list(set(emails))

def reverse_dns_lookup(ip):
    """Get all domains pointing to an IP"""
    domains = []
    
    try:
        reverse_ip = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(reverse_ip, 'PTR')
        domains = [str(rdata)[:-1] for rdata in answers]
    except:
        pass
    
    return domains

def get_ssl_certificate_chain(host):
    """Get full SSL certificate chain"""
    try:
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(), server_hostname=host) as sock:
            sock.connect((host, 443))
            certs = sock.getpeercert_chain()
            
            cert_chain = []
            for cert_der in certs:
                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                alt_names = []
                try:
                    san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    alt_names = [str(name.value) for name in san_ext.value]
                except:
                    pass
                
                cert_chain.append({
                    "subject": str(cert.subject),
                    "issuer": str(cert.issuer),
                    "valid_from": str(cert.not_valid_before_utc),
                    "valid_to": str(cert.not_valid_after_utc),
                    "alternative_names": alt_names
                })
            
            return cert_chain
    except:
        return []

def get_asn_info(ip):
    """Get ASN and network information"""
    try:
        response = requests.get(f"https://ipinfo.io/{ip}", timeout=5)
        data = response.json()
        return {
            "asn": data.get("asn", ""),
            "org": data.get("org", ""),
            "isp": data.get("isp", ""),
            "country": data.get("country", ""),
            "region": data.get("region", ""),
            "city": data.get("city", ""),
            "coordinates": data.get("loc", "")
        }
    except:
        return {}

def get_geolocation(ip):
    """Get detailed geolocation info"""
    try:
        response = requests.get(f"https://ip-api.com/json/{ip}", timeout=5)
        data = response.json()
        
        if data.get("status") == "success":
            return {
                "country": data.get("country"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "latitude": data.get("lat"),
                "longitude": data.get("lon"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "asn": data.get("as")
            }
    except:
        pass
    
    return {}

# ========== ADVANCED RECON FUNCTIONS ==========

def analyze_http_methods(domain):
    """Test HTTP methods (GET, POST, PUT, DELETE, OPTIONS, TRACE)"""
    methods = {}
    methods_to_test = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD', 'PATCH', 'TRACE']
    
    for method in methods_to_test:
        try:
            response = requests.request(method, f"https://{domain}", timeout=5, allow_redirects=False)
            methods[method] = {
                "status": response.status_code,
                "allowed": response.status_code != 405
            }
        except:
            methods[method] = {"status": "error", "allowed": False}
    
    return methods

def extract_metadata(domain):
    """Extract metadata from HTML (title, description, author, etc.)"""
    metadata = {}
    
    try:
        response = requests.get(f"https://{domain}", timeout=5, allow_redirects=True)
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')
        
        # Extract common metadata
        metadata['title'] = soup.title.string if soup.title else 'N/A'
        
        meta_tags = soup.find_all('meta')
        for tag in meta_tags:
            name = tag.get('name') or tag.get('property')
            content = tag.get('content')
            if name and content:
                metadata[name] = content
        
        # Extract headings
        h1 = [h.text for h in soup.find_all('h1')]
        h2 = [h.text for h in soup.find_all('h2')]
        if h1: metadata['h1_tags'] = h1[:3]
        if h2: metadata['h2_tags'] = h2[:3]
        
    except:
        pass
    
    return metadata

def detect_waf(domain):
    """Attempt to detect Web Application Firewall"""
    waf_indicators = {
        'Cloudflare': ['__cfduid', 'cf_clearance', 'cloudflare'],
        'AWS WAF': ['aws-waf', 'x-amzn-waf'],
        'ModSecurity': ['modsecurity', 'NAXSI'],
        'Imperva': ['imperva', '_Incap_Session'],
        'Akamai': ['akamai', 'x-akamai'],
        'Sucuri': ['sucuri', 'cloudproxy']
    }
    
    detected_waf = []
    
    try:
        response = requests.get(f"https://{domain}", timeout=5, allow_redirects=True)
        headers = response.headers
        html = response.text
        
        for waf_name, indicators in waf_indicators.items():
            for indicator in indicators:
                if indicator.lower() in str(headers).lower() or indicator.lower() in html.lower():
                    detected_waf.append(waf_name)
                    break
    except:
        pass
    
    return list(set(detected_waf))

def extract_links(domain):
    """Extract all internal and external links from website"""
    links = {'internal': [], 'external': []}
    
    try:
        response = requests.get(f"https://{domain}", timeout=5, allow_redirects=True)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        for link in soup.find_all('a', href=True):
            url = link['href']
            if url.startswith('http'):
                if domain in url:
                    links['internal'].append(url)
                else:
                    links['external'].append(url)
            elif url.startswith('/'):
                links['internal'].append(f"https://{domain}{url}")
    except:
        pass
    
    return {
        'internal_count': len(links['internal']),
        'external_count': len(links['external']),
        'internal_links': links['internal'][:10],
        'external_links': links['external'][:10]
    }

def analyze_cookies(domain):
    """Analyze cookies set by domain"""
    cookies_info = {}
    
    try:
        response = requests.get(f"https://{domain}", timeout=5, allow_redirects=True)
        
        for cookie in response.cookies:
            cookies_info[cookie.name] = {
                'value': cookie.value[:50] if len(cookie.value) > 50 else cookie.value,
                'domain': cookie.domain,
                'path': cookie.path,
                'secure': cookie.secure,
                'httponly': cookie.has_nonstandard_attr('HttpOnly')
            }
    except:
        pass
    
    return cookies_info

def parse_robots_txt(domain):
    """Parse robots.txt file"""
    robots_data = {'user_agents': defaultdict(dict), 'sitemaps': []}
    
    try:
        response = requests.get(f"https://{domain}/robots.txt", timeout=5)
        if response.status_code == 200:
            lines = response.text.split('\n')
            current_ua = '*'
            
            for line in lines:
                line = line.strip()
                if line.startswith('User-agent:'):
                    current_ua = line.split(':', 1)[1].strip()
                elif line.startswith('Disallow:'):
                    path = line.split(':', 1)[1].strip()
                    if current_ua not in robots_data['user_agents']:
                        robots_data['user_agents'][current_ua] = {'disallow': [], 'allow': []}
                    robots_data['user_agents'][current_ua]['disallow'].append(path)
                elif line.startswith('Allow:'):
                    path = line.split(':', 1)[1].strip()
                    if current_ua not in robots_data['user_agents']:
                        robots_data['user_agents'][current_ua] = {'disallow': [], 'allow': []}
                    robots_data['user_agents'][current_ua]['allow'].append(path)
                elif line.startswith('Sitemap:'):
                    robots_data['sitemaps'].append(line.split(':', 1)[1].strip())
    except:
        pass
    
    return dict(robots_data)

def parse_sitemap(domain):
    """Parse sitemap.xml"""
    urls = []
    
    try:
        response = requests.get(f"https://{domain}/sitemap.xml", timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'xml')
            for url in soup.find_all('url')[:50]:
                loc = url.find('loc')
                if loc:
                    urls.append(loc.text)
    except:
        pass
    
    return {'urls': urls, 'count': len(urls)}

def check_http_security_config(domain):
    """Advanced HTTP security configuration analysis"""
    config = {}
    
    try:
        response = requests.get(f"https://{domain}", timeout=5, allow_redirects=True)
        headers = response.headers
        
        config['https'] = True
        config['hsts_enabled'] = 'Strict-Transport-Security' in headers
        config['csp_enabled'] = 'Content-Security-Policy' in headers
        config['xfo_enabled'] = 'X-Frame-Options' in headers
        config['x_content_type'] = 'X-Content-Type-Options' in headers
        config['cors_enabled'] = 'Access-Control-Allow-Origin' in headers
        config['server_header_present'] = 'Server' in headers
        config['powered_by_present'] = 'X-Powered-By' in headers
        
        if config['server_header_present']:
            config['server'] = headers.get('Server', '')
        
    except:
        pass
    
    return config

def enumerate_common_paths(domain):
    """Check for common admin paths and sensitive files"""
    common_paths = [
        '/admin', '/admin/', '/admin.php', '/administrator',
        '/wp-admin', '/wp-login', '/user/login', '/login',
        '/config', '/.env', '/.git', '/.git/config',
        '/backup', '/backup.zip', '/database.sql',
        '/.well-known/security.txt', '/security.txt',
        '/.htaccess', '/web.config',
        '/xmlrpc.php', '/api', '/api/docs',
        '/.env.example', '/composer.json',
        '/package.json', '/yarn.lock'
    ]
    
    found_paths = []
    
    for path in common_paths:
        try:
            response = requests.head(f"https://{domain}{path}", timeout=3, allow_redirects=False)
            if response.status_code != 404:
                found_paths.append({
                    'path': path,
                    'status': response.status_code
                })
        except:
            pass
    
    return found_paths

def check_spf_dkim_dmarc(domain):
    """Check SPF, DKIM, and DMARC records"""
    email_security = {}
    
    try:
        # SPF
        try:
            spf_answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in spf_answers:
                txt_data = str(rdata)
                if 'v=spf1' in txt_data:
                    email_security['spf'] = txt_data
        except:
            email_security['spf'] = None
        
        # DMARC
        try:
            dmarc_answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
            for rdata in dmarc_answers:
                email_security['dmarc'] = str(rdata)
        except:
            email_security['dmarc'] = None
        
        # DKIM (common selectors)
        dkim_selectors = ['default', 'mail', 'selector1', 'selector2', 'google', 'k1']
        email_security['dkim'] = {}
        
        for selector in dkim_selectors:
            try:
                dkim_answers = dns.resolver.resolve(f"{selector}._domainkey.{domain}", 'TXT')
                email_security['dkim'][selector] = 'Present'
            except:
                email_security['dkim'][selector] = 'Not Found'
    except:
        pass
    
    return email_security

def check_cdn_and_proxies(domain):
    """Detect CDN, proxies, and cloaking services"""
    cdn_info = {}
    
    try:
        ip = socket.gethostbyname(domain)
        
        # Popular CDN IP ranges (simplified check)
        cdns = {
            'Cloudflare': ['1.0.0', '103.21', '103.22', '104.16'],
            'Akamai': ['184.84', '184.85', '2.16', '2.17'],
            'Fastly': ['151.101', '23.235'],
            'AWS CloudFront': ['52.84', '52.85'],
            'Azure CDN': ['13.107', '13.109'],
            'Google CDN': ['34.64', '34.65']
        }
        
        for cdn_name, prefixes in cdns.items():
            if any(ip.startswith(prefix) for prefix in prefixes):
                cdn_info['detected_cdn'] = cdn_name
                break
        
        cdn_info['ip'] = ip
        
    except:
        pass
    
    return cdn_info

def analyze_response_timing(domain):
    """Analyze response times and performance indicators"""
    timing = {}
    
    try:
        import time as t
        
        start = t.time()
        response = requests.get(f"https://{domain}", timeout=10)
        end = t.time()
        
        timing['response_time_ms'] = round((end - start) * 1000)
        timing['status_code'] = response.status_code
        timing['content_length'] = len(response.content)
        timing['compressed'] = 'Content-Encoding' in response.headers
        
        if 'Server' in response.headers:
            timing['server'] = response.headers['Server']
    except:
        pass
    
    return timing

def check_certificate_pinning(domain):
    """Check for certificate pinning"""
    pinning_info = {}
    
    try:
        response = requests.get(f"https://{domain}", timeout=5)
        headers = response.headers
        
        pinning_info['pins_present'] = 'Public-Key-Pins' in headers
        if pinning_info['pins_present']:
            pinning_info['pins'] = headers.get('Public-Key-Pins', '')
    except:
        pass
    
    return pinning_info

def detect_framework_versions(domain):
    """Try to detect specific versions of frameworks"""
    versions = {}
    
    try:
        response = requests.get(f"https://{domain}", timeout=5)
        html = response.text
        headers = response.headers
        
        # Version detection patterns
        patterns = {
            'WordPress': r"wp-content/themes/[^/]+/style\.css\?ver=([^\s&\"']+)",
            'jQuery': r"jquery[.-]?([0-9.]+)",
            'Bootstrap': r"bootstrap[.-]?([0-9.]+)",
            'Laravel': r"Laravel/([0-9.]+)",
            'Express': r"Express/([0-9.]+)"
        }
        
        for name, pattern in patterns.items():
            matches = re.findall(pattern, html + str(headers), re.IGNORECASE)
            if matches:
                versions[name] = matches[0]
    except:
        pass
    
    return versions

def analyze_dns_propagation(domain):
    """Check DNS records from multiple resolvers"""
    propagation = {}
    
    try:
        resolvers_to_check = [
            ('Google', '8.8.8.8'),
            ('Cloudflare', '1.1.1.1'),
            ('OpenDNS', '208.67.222.222'),
            ('Quad9', '9.9.9.9')
        ]
        
        for name, resolver_ip in resolvers_to_check:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [resolver_ip]
                answers = resolver.resolve(domain, 'A')
                propagation[name] = [str(rdata) for rdata in answers]
            except:
                propagation[name] = []
    except:
        pass
    
    return propagation

def extract_comments_and_secrets(domain):
    """Extract HTML/CSS/JS comments that may contain sensitive info"""
    findings = {'html_comments': [], 'todo_items': [], 'suspicious_patterns': []}
    
    try:
        response = requests.get(f"https://{domain}", timeout=5)
        html = response.text
        
        # Extract HTML comments
        comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
        findings['html_comments'] = [c.strip()[:100] for c in comments if len(c.strip()) > 0][:10]
        
        # Find TODO/FIXME/HACK comments
        todos = re.findall(r'(TODO|FIXME|HACK|BUG|DEBUG|REMOVE)[:\s]*(.+?)[\n\r]', html, re.IGNORECASE)
        findings['todo_items'] = [f"{t[0]}: {t[1].strip()}" for t in todos][:10]
        
        # Look for potential secrets
        suspicious = re.findall(r'(api[_-]?key|token|secret|password|apikey)[\s=:]*["\']?([a-zA-Z0-9]+)["\']?', html, re.IGNORECASE)
        findings['suspicious_patterns'] = len(suspicious)
    except:
        pass
    
    return findings

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/category/infrastructure', methods=['POST'])
def scan_infrastructure():
    """Run all Infrastructure scans sequentially"""
    data = request.json
    domain = data.get('domain', '').strip()
    
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    parsed_url = urlparse(domain)
    if parsed_url.scheme:
        domain = parsed_url.netloc
    
    try:
        results = {
            'category': 'Infrastructure',
            'domain': domain,
            'DNS Records': get_dns_records(domain),
            'WHOIS': get_whois_info(domain),
            'Port Scan': {},
            'Geolocation': {},
            'CDN Detection': check_cdn_and_proxies(domain)
        }
        
        # Get real IP for port scanning
        ip = get_real_ip(domain)
        if ip:
            results['Port Scan'] = {'ip': ip, 'open_ports': scan_common_ports(ip)}
            results['Geolocation'] = get_geolocation(ip)
        
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/category/security', methods=['POST'])
def scan_security():
    """Run all Security scans sequentially"""
    data = request.json
    domain = data.get('domain', '').strip()
    
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    parsed_url = urlparse(domain)
    if parsed_url.scheme:
        domain = parsed_url.netloc
    
    try:
        results = {
            'category': 'Security',
            'domain': domain,
            'Security Headers': analyze_security_headers(domain),
            'SSL Certificate': get_ssl_certificate_info(domain),
            'WAF Detection': detect_waf(domain),
            'Email Security': check_spf_dkim_dmarc(domain),
            'HTTP Security': check_http_security_config(domain)
        }
        
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/category/technology', methods=['POST'])
def scan_technology():
    """Run all Technology scans sequentially"""
    data = request.json
    domain = data.get('domain', '').strip()
    
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    parsed_url = urlparse(domain)
    if parsed_url.scheme:
        domain = parsed_url.netloc
    
    try:
        results = {
            'category': 'Technology',
            'domain': domain,
            'Detected Technologies': detect_technologies(domain),
            'Framework Versions': detect_framework_versions(domain),
            'Metadata': extract_metadata(domain),
            'HTTP Methods': analyze_http_methods(domain)
        }
        
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/category/content', methods=['POST'])
def scan_content():
    """Run all Content scans sequentially"""
    data = request.json
    domain = data.get('domain', '').strip()
    
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    parsed_url = urlparse(domain)
    if parsed_url.scheme:
        domain = parsed_url.netloc
    
    try:
        results = {
            'category': 'Content',
            'domain': domain,
            'Links': extract_links(domain),
            'Common Paths': enumerate_common_paths(domain),
            'Robots.txt': parse_robots_txt(domain),
            'Sitemap.xml': parse_sitemap(domain),
            'Secrets & Comments': extract_comments_and_secrets(domain)
        }
        
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/category/performance', methods=['POST'])
def scan_performance():
    """Run all Performance scans sequentially"""
    data = request.json
    domain = data.get('domain', '').strip()
    
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    parsed_url = urlparse(domain)
    if parsed_url.scheme:
        domain = parsed_url.netloc
    
    try:
        results = {
            'category': 'Performance',
            'domain': domain,
            'Response Timing': analyze_response_timing(domain),
            'Cookies': analyze_cookies(domain),
            'DNS Propagation': analyze_dns_propagation(domain)
        }
        
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/scan/<category>/<scan_name>', methods=['POST'])
def scan_specific(category, scan_name):
    """Run a specific scan within a category and return only that result."""
    data = request.json or {}
    domain = data.get('domain', '').strip()

    if not domain:
        return jsonify({'error': 'Domain is required'}), 400

    parsed_url = urlparse(domain)
    if parsed_url.scheme:
        domain = parsed_url.netloc

    # normalize inputs
    category = category.lower()
    scan_name = scan_name.lower()

    try:
        results = {'category': category.capitalize(), 'domain': domain}

        # Infrastructure
        if category == 'infrastructure':
            if scan_name == 'dns':
                results['DNS Records'] = get_dns_records(domain)
            elif scan_name == 'whois':
                results['WHOIS'] = get_whois_info(domain)
            elif scan_name == 'ports':
                ip = get_real_ip(domain)
                results['Port Scan'] = {'ip': ip, 'open_ports': scan_common_ports(ip) if ip else []}
            elif scan_name == 'geolocation':
                ip = get_real_ip(domain)
                results['Geolocation'] = get_geolocation(ip) if ip else {}
            elif scan_name == 'cdn':
                results['CDN Detection'] = check_cdn_and_proxies(domain)

        # Security
        elif category == 'security':
            if scan_name == 'headers':
                results['Security Headers'] = analyze_security_headers(domain)
            elif scan_name == 'ssl':
                results['SSL Certificate'] = get_ssl_certificate_info(domain)
            elif scan_name == 'waf':
                results['WAF Detection'] = detect_waf(domain)
            elif scan_name == 'email':
                results['Email Security'] = check_spf_dkim_dmarc(domain)
            elif scan_name == 'http':
                results['HTTP Security'] = check_http_security_config(domain)

        # Technology
        elif category == 'technology':
            if scan_name == 'technologies':
                results['Detected Technologies'] = detect_technologies(domain)
            elif scan_name == 'versions':
                results['Framework Versions'] = detect_framework_versions(domain)
            elif scan_name == 'metadata':
                results['Metadata'] = extract_metadata(domain)
            elif scan_name == 'http_methods':
                results['HTTP Methods'] = analyze_http_methods(domain)

        # Content
        elif category == 'content':
            if scan_name == 'links':
                results['Links'] = extract_links(domain)
            elif scan_name == 'paths':
                results['Common Paths'] = enumerate_common_paths(domain)
            elif scan_name == 'robots':
                results['Robots.txt'] = parse_robots_txt(domain)
            elif scan_name == 'sitemap':
                results['Sitemap.xml'] = parse_sitemap(domain)
            elif scan_name == 'secrets':
                results['Secrets & Comments'] = extract_comments_and_secrets(domain)

        # Performance
        elif category == 'performance':
            if scan_name == 'timing':
                results['Response Timing'] = analyze_response_timing(domain)
            elif scan_name == 'cookies':
                results['Cookies'] = analyze_cookies(domain)
            elif scan_name == 'dns_propagation':
                results['DNS Propagation'] = analyze_dns_propagation(domain)

        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analyze', methods=['POST'])
def analyze():
    """Legacy endpoint - kept for compatibility"""
    data = request.json
    domain = data.get('domain', '').strip()
    
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    parsed_url = urlparse(domain)
    if parsed_url.scheme:
        domain = parsed_url.netloc
    
    results = {}
    
    # Check if using Cloudflare
    results['using_cloudflare'] = is_using_cloudflare(domain)
    results['domain'] = domain
    results['visible_ip'] = get_real_ip(domain)
    results['web_server'] = detect_web_server(domain)
    results['historical_ips'] = get_domain_historical_ip_address(domain)
    
    return jsonify(results)

@app.route('/api/version', methods=['GET'])
def get_version():
    return jsonify({'version': VERSION})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
