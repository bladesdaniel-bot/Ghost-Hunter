# config.py
"""
Security Tool Configuration
"""

# Default settings
DEFAULT_TIMEOUT = 5
DEFAULT_THREADS = 10

# Common ports for scanning
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
    445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900
]

# Security headers to check
SECURITY_HEADERS = [
    'X-Content-Type-Options',
    'X-Frame-Options', 
    'X-XSS-Protection',
    'Strict-Transport-Security',
    'Content-Security-Policy'
]

# Vulnerable services and their common ports
VULNERABLE_SERVICES = {
    'FTP': [21],
    'SSH': [22],
    'Telnet': [23],
    'SMTP': [25],
    'DNS': [53],
    'HTTP': [80],
    'POP3': [110],
    'IMAP': [143],
    'HTTPS': [443],
    'RDP': [3389]
}
