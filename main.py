from modules.port_scanner import PortScanner
from modules.service_detect import ServiceDetector
from modules.os_detect import OSDetector
from modules.vuln_checks import VulnScanner
from utils.report_gen import generate_report
from utils.logger import log_info

if __name__ == "__main__":
    print(r"""
  __  __ _       _   _                         
 |  \/  (_)     (_) | |                        
 | \  / |_ _ __  _  | |     ___  ___ ___ _   _ 
 | |\/| | | '_ \| | | |    / _ \/ __/ __| | | |
 | |  | | | | | | | | |___|  __/\__ \__ \ |_| |
 |_|  |_|_|_| |_|_| |______\___||___/___/\__,_|
                  
    """)
    
    # 1. Input
    target = input("Enter Target IP/URL (e.g. scanme.nmap.org): ").strip()
    if target.startswith("http"):
        target = target.split("//")[1].split("/")[0]
        
    scan_data = {}

    # 2. Port Scan
    scanner = PortScanner(target)
    open_ports = scanner.run()
    scan_data['open_ports'] = open_ports

    if open_ports:
        # 3. Service Detection
        serv_det = ServiceDetector(target, open_ports)
        services = serv_det.run()
        scan_data['services'] = services

        # 4. OS Detection
        os_det = OSDetector(target)
        os_info = os_det.run()
        scan_data['os_info'] = os_info

        # 5. Vulnerability Checks
        vuln_scan = VulnScanner(target, open_ports, services)
        vulns = vuln_scan.run()
        scan_data['vulns'] = vulns

        # 6. Generate Report
        generate_report(target, scan_data)
        
    else:
        log_info("No open ports found. Skipping remaining checks.")