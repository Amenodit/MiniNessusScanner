import requests
from utils.logger import log_info, log_warning, log_success

class VulnScanner:
    def __init__(self, target_ip, open_ports, services):
        self.target_ip = target_ip
        self.open_ports = open_ports
        self.services = services
        self.vulns = []

    def add_vuln(self, name, severity, description, recommendation):
        self.vulns.append({
            "name": name,
            "severity": severity,
            "description": description,
            "recommendation": recommendation
        })

    def check_missing_headers(self):
        # Check 1: Missing Security Headers
        if 80 in self.open_ports or 8080 in self.open_ports:
            try:
                url = f"http://{self.target_ip}"
                res = requests.get(url, timeout=3)
                headers = res.headers
                
                if 'X-Frame-Options' not in headers:
                    self.add_vuln(
                        "Missing X-Frame-Options", 
                        "Medium", 
                        "The site is missing the 'X-Frame-Options' header, making it vulnerable to Clickjacking attacks.",
                        "Configure your web server (Apache/Nginx) to send 'X-Frame-Options: DENY' or 'SAMEORIGIN'."
                    )
                
                if 'Content-Security-Policy' not in headers:
                    self.add_vuln(
                        "Missing CSP Header", 
                        "Low", 
                        "No Content Security Policy (CSP) detected. This increases the risk of XSS attacks.",
                        "Implement a 'Content-Security-Policy' header to restrict where scripts and resources can be loaded from."
                    )
            except:
                pass

    def check_open_dirs(self):
        # Check 2: Open Directory Listing
        if 80 in self.open_ports:
            try:
                for path in ['/images/', '/uploads/', '/files/', '/static/']:
                    url = f"http://{self.target_ip}{path}"
                    res = requests.get(url, timeout=3)
                    if "Index of" in res.text:
                        self.add_vuln(
                            "Open Directory Listing", 
                            "Medium", 
                            f"Directory listing is enabled at {path}. Attackers can view all files.",
                            "Disable directory indexing in your web server config (e.g., 'Options -Indexes' for Apache)."
                        )
                        break
            except:
                pass

    def check_default_creds(self):
        # Check 3: Default Credentials
        if 80 in self.open_ports:
            try:
                url = f"http://{self.target_ip}/admin"
                res = requests.get(url, auth=('admin', 'admin'), timeout=3)
                if res.status_code == 200:
                     self.add_vuln(
                         "Default Credentials Found", 
                         "High", 
                         "Successfully logged into /admin using 'admin:admin'.",
                         "Immediately change the default password for the administrator account."
                     )
            except:
                pass

    def check_outdated_services(self):
        # Check 4: Outdated Service Versions
        for port, banner in self.services.items():
            if "Apache/2.2" in str(banner) or "PHP/5" in str(banner):
                self.add_vuln(
                    "Outdated Software Version", 
                    "High", 
                    f"Old version detected on port {port}: {banner}. It may have known exploits.",
                    "Upgrade the service to the latest stable version and apply security patches."
                )

    def check_anonymous_ftp(self):
        # Check 5: Anonymous FTP
        if 21 in self.open_ports:
            # Simulating logic for demonstration
            if "vsftpd 2.3.4" in str(self.services.get(21, "")):
                 self.add_vuln(
                     "Backdoored FTP Service", 
                     "Critical", 
                     "vsftpd 2.3.4 backdoor detected on Port 21.",
                     "Stop the FTP service immediately and replace the compromised binary."
                 )

    def run(self):
        log_info("Running Vulnerability Checks...")
        self.check_missing_headers()
        self.check_open_dirs()
        self.check_default_creds()
        self.check_outdated_services()
        self.check_anonymous_ftp()
        
        return self.vulns
