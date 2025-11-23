import socket
from utils.logger import log_info, log_success

class ServiceDetector:
    def __init__(self, target_ip, open_ports):
        self.target_ip = target_ip
        self.open_ports = open_ports
        self.services = {}

    def get_banner(self, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((self.target_ip, port))
            # Send trigger for HTTP
            if port in [80, 8080, 443]:
                s.send(b'HEAD / HTTP/1.0\r\n\r\n')
            
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            s.close()
            return banner
        except:
            return None

    def run(self):
        log_info("Starting Service Detection...")
        for port in self.open_ports:
            banner = self.get_banner(port)
            if banner:
                clean_banner = banner.split('\n')[0][:50]
                self.services[port] = clean_banner
                log_success(f"Port {port}: {clean_banner}")
            else:
                self.services[port] = "Unknown"
        return self.services