from scapy.all import sr1, IP, ICMP
from utils.logger import log_info, log_success, log_warning

class OSDetector:
    def __init__(self, target_ip):
        self.target_ip = target_ip

    def run(self):
        log_info(f"Attempting OS Detection on {self.target_ip} (requires Root/Admin)...")
        try:
            # Send 1 ICMP packet
            ans = sr1(IP(dst=self.target_ip)/ICMP(), timeout=2, verbose=0)
            if ans:
                ttl = ans.ttl
                if ttl <= 64:
                    os_guess = "Linux/Unix (TTL ~64)"
                elif ttl <= 128:
                    os_guess = "Windows (TTL ~128)"
                else:
                    os_guess = "Unknown (TTL > 128)"
                
                log_success(f"OS Detected: {os_guess}")
                return os_guess
            else:
                log_warning("No response for OS Detection.")
                return "Unknown"
        except Exception as e:
            log_warning(f"OS Detection Failed (Need Admin/Sudo?): {e}")
            return "Unknown"