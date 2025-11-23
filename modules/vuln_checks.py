import requests
from utils.logger import log_info, log_warning, log_success

class VulnScanner:
    def __init__(self, target_ip, open_ports, services):
        self.target_ip = target_ip
        self.open_ports = open_ports
        self.services = services
        self.vulns = []

    def check_missing_headers(self):
        # Check 1: Missing Security Headers
        if 80 in self.open_ports or 8080 in self.open_ports:
            try:
                url = f"http://{self.target_ip}"
                res = requests.get(url, timeout=3)
                headers = res.headers
                if 'X-Frame-Options' not in headers:
                    self.vulns.append({"name": "Missing X-Frame-Options", "severity": "Medium", "description": "Site is vulnerable to Clickjacking."})
                if 'Content-Security-Policy' not in headers:
                    self.vulns.append({"name": "Missing CSP", "severity": "Low", "description": "Missing Content Security Policy."})
            except:
                pass

    def check_open_dirs(self):
        # Check 2: Open Directory Listing
        if 80 in self.open_ports:
            try:
                # Common test paths
                for path in ['/images/', '/uploads/', '/files/']:
                    url = f"http://{self.target_ip}{path}"
                    res = requests.get(url, timeout=3)
                    if "Index of" in res.text:
                        self.vulns.append({"name": "Open Directory Listing", "severity": "Medium", "description": f"Directory listing enabled at {path}"})
                        break
            except:
                pass

    def check_default_creds(self):
        # Check 3: Default Credentials (Basic Auth)
        if 80 in self.open_ports:
            try:
                url = f"http://{self.target_ip}/admin"
                # Try admin:admin
                res = requests.get(url, auth=('admin', 'admin'), timeout=3)
                if res.status_code == 200:
                     self.vulns.append({"name": "Default Credentials", "severity": "High", "description": "Found valid login admin:admin"})
            except:
                pass

    def check_outdated_services(self):
        # Check 4: Outdated Service Versions (Simulated)
        for port, banner in self.services.items():
            if "Apache/2.2" in str(banner) or "PHP/5" in str(banner):
                self.vulns.append({"name": "Outdated Service", "severity": "High", "description": f"Old version detected on port {port}: {banner}"})

    def check_anonymous_ftp(self):
        # Check 5: Anonymous FTP (Stub for logic)
        if 21 in self.open_ports:
            # In real implementation, use ftplib. Here we check banner for simplicity
            if "vsftpd 2.3.4" in str(self.services.get(21, "")):
                 self.vulns.append({"name": "Backdoored FTP", "severity": "Critical", "description": "vsftpd 2.3.4 backdoor detected."})

    def run(self):
        log_info("Running Vulnerability Checks...")
        self.check_missing_headers()
        self.check_open_dirs()
        self.check_default_creds()
        self.check_outdated_services()
        self.check_anonymous_ftp()
        
        if self.vulns:
            log_warning(f"Found {len(self.vulns)} vulnerabilities!")
        else:
            log_success("No simple vulnerabilities found.")
        return self.vulns