# Comprehensive Vulnerability Scanner - Alternative to Nikto
# This module provides vulnerability scanning functions without Flask routes

import requests
import socket
import ssl
import json
from datetime import datetime
import re
import urllib.parse
import threading
import time
import subprocess
import os



# Comprehensive vulnerability patterns
VULNERABILITY_PATTERNS = {
    'sql_injection': [
        r"sql.*error|mysql.*error|syntax.*error|database.*error",
        r"ORA-\d+|Microsoft.*ODBC.*SQL|SQLServer JDBC",
        r"PostgreSQL.*ERROR|Warning.*mysql_|valid MySQL result",
        r"SQLite.*error|SQLite.*exception",
        r"PostgreSQL.*ERROR|Warning.*pg_",
        r"Microsoft.*SQL.*Server.*error"
    ],
    'xss': [
        r"<script[^>]*>.*</script>",
        r"javascript:",
        r"on\w+\s*=",
        r"<iframe[^>]*>",
        r"<object[^>]*>",
        r"<embed[^>]*>",
        r"<link[^>]*>",
        r"<meta[^>]*>"
    ],
    'directory_traversal': [
        r"\.\./|\.\.\\|\.\.%2f|\.\.%5c",
        r"etc/passwd|boot\.ini|win\.ini",
        r"proc/self/environ|proc/version",
        r"\.\.%2f\.\.%2f|\.\.%5c\.\.%5c",
        r"\.\.%252f|\.\.%255c"
    ],
    'command_injection': [
        r"uid=\d+|gid=\d+|groups=\d+",
        r"Microsoft Windows|Linux|Unix",
        r"root:|bin/bash|cmd\.exe",
        r"PATH=|PWD=|HOME=",
        r"whoami|id|pwd|ls|dir"
    ],
    'file_inclusion': [
        r"include.*\.\./|require.*\.\./",
        r"fopen.*\.\./|file_get_contents.*\.\./",
        r"include_once.*\.\./|require_once.*\.\./",
        r"readfile.*\.\./|show_source.*\.\./"
    ]
}

# Comprehensive dangerous paths
DANGEROUS_PATHS = [
    # Admin interfaces
    '/admin', '/administrator', '/admin.php', '/admin.html', '/admin.asp',
    '/wp-admin', '/wp-login.php', '/login', '/login.php', '/login.asp',
    '/phpmyadmin', '/pma', '/mysql', '/sql', '/phpmyadmin/index.php',
    '/adminer.php', '/adminer', '/admin.php', '/admin/', '/admin/index.php',
    
    # Configuration files
    '/.env', '/config.php', '/config.inc.php', '/configuration.php',
    '/wp-config.php', '/settings.php', '/config.json', '/config.xml',
    '/web.config', '/app.config', '/database.yml', '/database.yaml',
    '/config.yaml', '/config.yml', '/.htaccess', '/.htpasswd',
    
    # Backup files
    '/backup', '/backups', '/backup.sql', '/database.sql',
    '/dump.sql', '/backup.tar.gz', '/backup.zip', '/backup.rar',
    '/site_backup', '/db_backup', '/files_backup',
    
    # Debug and test files
    '/test', '/debug', '/test.php', '/info.php', '/phpinfo.php',
    '/test.html', '/debug.html', '/status', '/server-info',
    '/server-status', '/status.php', '/info.asp', '/test.asp',
    
    # Sensitive directories
    '/logs', '/log', '/tmp', '/temp', '/cache', '/caches',
    '/uploads', '/files', '/documents', '/private', '/secure',
    '/confidential', '/internal', '/restricted',
    
    # Common files
    '/robots.txt', '/sitemap.xml', '/crossdomain.xml', '/favicon.ico',
    '/.git', '/.svn', '/.hg', '/.bzr', '/.git/config', '/.svn/entries',
    
    # Development files
    '/package.json', '/composer.json', '/requirements.txt', '/Gemfile',
    '/Dockerfile', '/docker-compose.yml', '/.env.example', '/.env.local',
    
    # CMS specific
    '/wp-content/uploads', '/wp-content/plugins', '/wp-content/themes',
    '/wp-includes', '/wp-config-sample.php', '/readme.html',
    '/administrator', '/administrator/index.php', '/joomla',
    
    # Framework specific
    '/app', '/src', '/vendor', '/node_modules', '/bower_components',
    '/public', '/resources', '/storage', '/database/migrations'
]

# Security headers to check
SECURITY_HEADERS = {
    'X-Frame-Options': {'severity': 'Medium', 'description': 'Prevents clickjacking attacks'},
    'X-XSS-Protection': {'severity': 'Medium', 'description': 'Enables XSS filtering'},
    'X-Content-Type-Options': {'severity': 'Medium', 'description': 'Prevents MIME type sniffing'},
    'Strict-Transport-Security': {'severity': 'High', 'description': 'Enforces HTTPS'},
    'Content-Security-Policy': {'severity': 'High', 'description': 'Prevents XSS and data injection'},
    'X-Permitted-Cross-Domain-Policies': {'severity': 'Low', 'description': 'Controls cross-domain policies'},
    'Referrer-Policy': {'severity': 'Low', 'description': 'Controls referrer information'},
    'Permissions-Policy': {'severity': 'Medium', 'description': 'Controls browser features'},
    'Cross-Origin-Embedder-Policy': {'severity': 'Medium', 'description': 'Controls cross-origin embedding'},
    'Cross-Origin-Opener-Policy': {'severity': 'Medium', 'description': 'Controls cross-origin window access'}
}

def deduplicate_vulnerabilities(vulnerabilities):
    """Remove duplicate or very similar vulnerabilities"""
    seen = set()
    unique_vulns = []
    
    for vuln in vulnerabilities:
        # Create a key based on type, description, and URL (without payload)
        base_url = vuln.get('url', '').split('?')[0] if '?' in vuln.get('url', '') else vuln.get('url', '')
        key = (vuln.get('type', ''), vuln.get('description', ''), base_url)
        
        if key not in seen:
            seen.add(key)
            unique_vulns.append(vuln)
    
    return unique_vulns

def run_comprehensive_scan(target_url, scan_options=None):
    """Run a comprehensive vulnerability scan"""
    if scan_options is None:
        scan_options = {
            'depth': 'medium',
            'timeout': '10',
            'threads': '5'
        }
    
    results = {
        'target': target_url,
        'timestamp': datetime.now().isoformat(),
        'vulnerabilities': [],
        'ssl_info': None,
        'status_code': None,
        'headers': None,
        'scan_summary': {}
    }
    
    try:
        # Basic connectivity test
        response = requests.get(target_url, timeout=10, allow_redirects=True)
        results['status_code'] = response.status_code
        results['headers'] = dict(response.headers)
        
        # Run all vulnerability checks
        vuln_checks = [
            check_security_headers,
            check_dangerous_paths,
            check_server_info,
            check_ssl_issues,
            check_sql_injection,
            check_xss_vulnerabilities,
            check_directory_traversal,
            check_command_injection,
            check_file_inclusion,
            check_cms_vulnerabilities,
            check_framework_vulnerabilities,
            check_api_vulnerabilities
        ]
        
        for check in vuln_checks:
            try:
                vulns = check(target_url, response)
                results['vulnerabilities'].extend(vulns)
            except Exception as e:
                print(f"Check failed: {e}")
                continue
        
        # SSL certificate check
        if target_url.startswith('https'):
            parsed_url = urllib.parse.urlparse(target_url)
            ssl_info = check_ssl_certificate(parsed_url.hostname)
            results['ssl_info'] = ssl_info
            if 'issues' in ssl_info:
                results['vulnerabilities'].extend(ssl_info['issues'])
        
        # Deduplicate similar vulnerabilities
        results['vulnerabilities'] = deduplicate_vulnerabilities(results['vulnerabilities'])
        
        # Generate scan summary
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for vuln in results['vulnerabilities']:
            severity = vuln.get('severity', 'Low')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        results['scan_summary'] = {
            'total_vulnerabilities': len(results['vulnerabilities']),
            'severity_breakdown': severity_counts,
            'scan_completed': True
        }
        
    except requests.exceptions.RequestException as e:
        results['vulnerabilities'].append({
            'type': 'Connection Error',
            'severity': 'High',
            'description': f'Unable to connect to target: {str(e)}'
        })
    
    return results

def check_security_headers(target_url, response):
    """Check for missing security headers"""
    vulnerabilities = []
    headers = response.headers
    
    for header, info in SECURITY_HEADERS.items():
        if header not in headers:
            vulnerabilities.append({
                'type': 'Missing Security Header',
                'severity': info['severity'],
                'description': f'{header} header not present - {info["description"]}',
                'recommendation': f'Add {header} header to improve security'
            })
    
    return vulnerabilities

def check_dangerous_paths(target_url, response):
    """Check for accessible dangerous paths"""
    vulnerabilities = []
    
    for path in DANGEROUS_PATHS:
        try:
            test_url = urllib.parse.urljoin(target_url, path)
            test_response = requests.get(test_url, timeout=5, allow_redirects=False)
            
            if test_response.status_code == 200:
                vulnerabilities.append({
                    'type': 'Sensitive Path Accessible',
                    'severity': 'High',
                    'description': f'Dangerous path accessible: {path}',
                    'url': test_url,
                    'status_code': test_response.status_code,
                    'content_length': len(test_response.content)
                })
            elif test_response.status_code in [301, 302, 307, 308]:
                vulnerabilities.append({
                    'type': 'Redirect Found',
                    'severity': 'Medium',
                    'description': f'Redirect found at: {path}',
                    'url': test_url,
                    'status_code': test_response.status_code
                })
        except:
            continue
    
    return vulnerabilities

def check_sql_injection(target_url, response):
    """Check for SQL injection vulnerabilities"""
    vulnerabilities = []
    found_params = set()  # Track which parameters already have SQL injection
    
    # Common SQL injection payloads - reduced set for efficiency
    sql_payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "' UNION SELECT NULL--"
    ]
    
    # Common parameters to test
    params = ['id', 'user', 'username', 'password', 'search', 'q', 'query', 'page', 'category']
    
    for param in params:
        if param in found_params:
            continue  # Skip if we already found SQL injection for this param
            
        for payload in sql_payloads:
            try:
                test_url = f"{target_url}?{param}={urllib.parse.quote(payload)}"
                test_response = requests.get(test_url, timeout=5)
                
                # Check for SQL error patterns
                for pattern in VULNERABILITY_PATTERNS['sql_injection']:
                    if re.search(pattern, test_response.text, re.IGNORECASE):
                        vulnerabilities.append({
                            'type': 'SQL Injection',
                            'severity': 'Critical',
                            'description': f'SQL injection vulnerability detected in parameter: {param}',
                            'url': test_url,
                            'payload': payload,
                            'evidence': re.search(pattern, test_response.text, re.IGNORECASE).group(),
                            'recommendation': 'Use parameterized queries and input validation'
                        })
                        found_params.add(param)
                        break  # Found vulnerability for this param, move to next param
                if param in found_params:
                    break  # Move to next parameter
            except:
                continue
    
    return vulnerabilities

def check_xss_vulnerabilities(target_url, response):
    """Check for XSS vulnerabilities"""
    vulnerabilities = []
    found_params = set()  # Track which parameters already have XSS
    
    # XSS payloads - reduced set for efficiency
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "';alert('XSS');//"
    ]
    
    params = ['search', 'q', 'query', 'name', 'comment', 'message', 'title', 'description']
    
    for param in params:
        if param in found_params:
            continue  # Skip if we already found XSS for this param
            
        for payload in xss_payloads:
            try:
                test_url = f"{target_url}?{param}={urllib.parse.quote(payload)}"
                test_response = requests.get(test_url, timeout=5)
                
                # Check if payload is reflected in response
                if payload in test_response.text:
                    vulnerabilities.append({
                        'type': 'Cross-Site Scripting (XSS)',
                        'severity': 'High',
                        'description': f'XSS vulnerability detected in parameter: {param}',
                        'url': test_url,
                        'payload': payload,
                        'recommendation': 'Implement proper input validation and output encoding'
                    })
                    found_params.add(param)
                    break  # Found vulnerability for this param, move to next param
            except:
                continue
    
    return vulnerabilities

def check_directory_traversal(target_url, response):
    """Check for directory traversal vulnerabilities"""
    vulnerabilities = []
    
    # Directory traversal payloads
    traversal_payloads = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd"
    ]
    
    params = ['file', 'path', 'page', 'include', 'doc', 'document']
    
    for param in params:
        for payload in traversal_payloads:
            try:
                test_url = f"{target_url}?{param}={urllib.parse.quote(payload)}"
                test_response = requests.get(test_url, timeout=5)
                
                # Check for directory traversal indicators
                for pattern in VULNERABILITY_PATTERNS['directory_traversal']:
                    if re.search(pattern, test_response.text, re.IGNORECASE):
                        vulnerabilities.append({
                            'type': 'Directory Traversal',
                            'severity': 'High',
                            'description': f'Potential directory traversal in parameter: {param}',
                            'url': test_url,
                            'payload': payload,
                            'evidence': re.search(pattern, test_response.text, re.IGNORECASE).group()
                        })
                        break
            except:
                continue
    
    return vulnerabilities

def check_command_injection(target_url, response):
    """Check for command injection vulnerabilities"""
    vulnerabilities = []
    found_params = set()  # Track which parameters already have command injection
    
    # Command injection payloads - test with one payload per parameter
    cmd_payloads = [
        "; ls",
        "| whoami", 
        "& dir"
    ]
    
    params = ['cmd', 'command', 'exec', 'system', 'ping', 'host']
    
    for param in params:
        if param in found_params:
            continue  # Skip if we already found command injection for this param
            
        for payload in cmd_payloads:
            try:
                test_url = f"{target_url}?{param}={urllib.parse.quote(payload)}"
                test_response = requests.get(test_url, timeout=5)
                
                # Check for command injection indicators
                for pattern in VULNERABILITY_PATTERNS['command_injection']:
                    if re.search(pattern, test_response.text, re.IGNORECASE):
                        vulnerabilities.append({
                            'type': 'Command Injection',
                            'severity': 'Critical',
                            'description': f'Command injection vulnerability detected in parameter: {param}',
                            'url': test_url,
                            'payload': payload,
                            'evidence': re.search(pattern, test_response.text, re.IGNORECASE).group(),
                            'recommendation': 'Implement proper input validation and use parameterized commands'
                        })
                        found_params.add(param)
                        break  # Found vulnerability for this param, move to next param
                if param in found_params:
                    break  # Move to next parameter
            except:
                continue
    
    return vulnerabilities

def check_file_inclusion(target_url, response):
    """Check for file inclusion vulnerabilities"""
    vulnerabilities = []
    
    # File inclusion payloads
    inclusion_payloads = [
        "../../../etc/passwd",
        "php://filter/read=convert.base64-encode/resource=index.php",
        "data://text/plain,<?php phpinfo(); ?>",
        "expect://whoami"
    ]
    
    params = ['file', 'include', 'page', 'path', 'doc']
    
    for param in params:
        for payload in inclusion_payloads:
            try:
                test_url = f"{target_url}?{param}={urllib.parse.quote(payload)}"
                test_response = requests.get(test_url, timeout=5)
                
                # Check for file inclusion indicators
                for pattern in VULNERABILITY_PATTERNS['file_inclusion']:
                    if re.search(pattern, test_response.text, re.IGNORECASE):
                        vulnerabilities.append({
                            'type': 'File Inclusion',
                            'severity': 'High',
                            'description': f'Potential file inclusion in parameter: {param}',
                            'url': test_url,
                            'payload': payload,
                            'evidence': re.search(pattern, test_response.text, re.IGNORECASE).group()
                        })
                        break
            except:
                continue
    
    return vulnerabilities

def check_cms_vulnerabilities(target_url, response):
    """Check for CMS-specific vulnerabilities"""
    vulnerabilities = []
    
    # WordPress specific checks
    wp_paths = [
        '/wp-content/uploads/',
        '/wp-includes/',
        '/wp-admin/admin-ajax.php',
        '/xmlrpc.php',
        '/wp-json/wp/v2/users'
    ]
    
    for path in wp_paths:
        try:
            test_url = urllib.parse.urljoin(target_url, path)
            test_response = requests.get(test_url, timeout=5)
            if test_response.status_code == 200:
                vulnerabilities.append({
                    'type': 'CMS Vulnerability',
                    'severity': 'Medium',
                    'description': f'WordPress path accessible: {path}',
                    'url': test_url
                })
        except:
            continue
    
    return vulnerabilities

def check_framework_vulnerabilities(target_url, response):
    """Check for framework-specific vulnerabilities"""
    vulnerabilities = []
    
    # Framework-specific checks
    framework_paths = [
        '/node_modules/',
        '/vendor/',
        '/bower_components/',
        '/.env',
        '/composer.json',
        '/package.json'
    ]
    
    for path in framework_paths:
        try:
            test_url = urllib.parse.urljoin(target_url, path)
            test_response = requests.get(test_url, timeout=5)
            if test_response.status_code == 200:
                vulnerabilities.append({
                    'type': 'Framework Vulnerability',
                    'severity': 'Medium',
                    'description': f'Framework file accessible: {path}',
                    'url': test_url
                })
        except:
            continue
    
    return vulnerabilities

def check_api_vulnerabilities(target_url, response):
    """Check for API-specific vulnerabilities"""
    vulnerabilities = []
    
    # API endpoints to check
    api_paths = [
        '/api/',
        '/api/v1/',
        '/api/v2/',
        '/rest/',
        '/graphql',
        '/swagger.json',
        '/swagger-ui/',
        '/api-docs/'
    ]
    
    for path in api_paths:
        try:
            test_url = urllib.parse.urljoin(target_url, path)
            test_response = requests.get(test_url, timeout=5)
            if test_response.status_code == 200:
                vulnerabilities.append({
                    'type': 'API Vulnerability',
                    'severity': 'Medium',
                    'description': f'API endpoint accessible: {path}',
                    'url': test_url
                })
        except:
            continue
    
    return vulnerabilities

def check_server_info(target_url, response):
    """Check for server information disclosure"""
    vulnerabilities = []
    headers = response.headers
    
    # Check for server information
    if 'Server' in headers:
        server_info = headers['Server']
        vulnerabilities.append({
            'type': 'Information Disclosure',
            'severity': 'Low',
            'description': f'Server header reveals: {server_info}',
            'recommendation': 'Consider hiding or modifying server header'
        })
    
    # Check for powered-by headers
    powered_by_headers = [h for h in headers.keys() if 'powered' in h.lower() or 'x-powered' in h.lower()]
    for header in powered_by_headers:
        vulnerabilities.append({
            'type': 'Information Disclosure',
            'severity': 'Low',
            'description': f'{header} reveals: {headers[header]}',
            'recommendation': 'Remove or modify technology disclosure headers'
        })
    
    return vulnerabilities

def check_ssl_issues(target_url, response):
    """Check for SSL issues"""
    vulnerabilities = []
    
    if target_url.startswith('https'):
        # Basic SSL checks
        if 'Strict-Transport-Security' not in response.headers:
            vulnerabilities.append({
                'type': 'SSL Configuration',
                'severity': 'Medium',
                'description': 'Missing HSTS header on HTTPS site',
                'recommendation': 'Add Strict-Transport-Security header'
            })
    
    return vulnerabilities

def check_ssl_certificate(hostname, port=443):
    """Check SSL certificate information"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                ssl_issues = []
                
                # Check certificate expiration
                from datetime import datetime
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_until_expiry = (not_after - datetime.now()).days
                
                if days_until_expiry < 30:
                    ssl_issues.append({
                        'type': 'SSL Certificate',
                        'severity': 'High',
                        'description': f'Certificate expires in {days_until_expiry} days',
                        'expiry_date': cert['notAfter']
                    })
                
                return {
                    'subject': dict(x[0] for x in cert['subject']),
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'not_after': cert['notAfter'],
                    'issues': ssl_issues
                }
    except Exception as e:
        return {'error': str(e)}