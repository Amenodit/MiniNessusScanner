import socket
import threading
from queue import Queue
from utils.logger import log_info, log_success

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 8080]

class PortScanner:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.open_ports = []
        self.lock = threading.Lock()
        self.queue = Queue()

    def scan_port(self, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex((self.target_ip, port))
            if result == 0:
                with self.lock:
                    self.open_ports.append(port)
                    log_success(f"Port {port} is OPEN")
            s.close()
        except:
            pass

    def worker(self):
        while not self.queue.empty():
            port = self.queue.get()
            self.scan_port(port)
            self.queue.task_done()

    def run(self):
        log_info(f"Starting Port Scan on {self.target_ip}...")
        for port in COMMON_PORTS:
            self.queue.put(port)
        
        threads = []
        for _ in range(10):
            t = threading.Thread(target=self.worker)
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
            
        return self.open_ports