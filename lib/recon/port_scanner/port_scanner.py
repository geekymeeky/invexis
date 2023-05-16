import json
from lib.shared.scanner import Scanner
from enum import Enum
import socket
from concurrent.futures import ThreadPoolExecutor
from urllib3.util.url import parse_url
# import nmap3


class PORT_SCANNER_MODES(Enum):
    QUICK = "quick"
    FULL = "full"

class PortScanner(Scanner):
    ALL_PORTS = range(1, 65535)

    with open("lib/recon/port_scanner/common_ports.json", "r") as f:
       COMMON_PORTS = json.load(f)

    with open("lib/recon/port_scanner/ports.json", "r") as f:
        PORTS = json.load(f)

    def __init__(self, target, mode):
        self.target = target
        self.mode: PORT_SCANNER_MODES = mode
        self.results = {}
        self.host = parse_url(target).host

    def scan(self):
        if self.mode == PORT_SCANNER_MODES.QUICK:
            ports = self.COMMON_PORTS
        elif self.mode == PORT_SCANNER_MODES.FULL:
            ports = self.PORTS
        else:
            raise Exception("Invalid mode")
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            for port in ports.keys():
                executor.submit(self._scan_port, port)

        return self.results

    
    def _scan_port(self, portAndProtocol):
        port, protocol = portAndProtocol.split("/")
        try:
            port = int(port)
            if protocol == "tcp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            elif protocol == "udp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            elif protocol == "sctp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_SEQPACKET)
            elif protocol == "dccp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DCCP)

            sock.settimeout(0.5)
            result = sock.connect_ex((self.host, port))

            if result == 0:
                self.results[portAndProtocol] = {
                    "status": "open",
                    "service": self.PORTS[portAndProtocol]["description"]
                }
            elif result == socket.timeout:
                self.results[portAndProtocol] = {
                    "status": "filtered",
                    "service": self.PORTS[portAndProtocol]["description"]
                }
            
       

            sock.close()
        except Exception as e:
            print(e)



# class NMAP_MODES(Enum):
#     QUICK = "quick"
#     DEFAULT = "default"
#     FULL = "full"
#     STEALTH = "stealth"


# class PortScanner(Scanner):
#     NMAP_COMMANDS = {
#         NMAP_MODES.DEFAULT: "-sV",
#         NMAP_MODES.QUICK: "-T4 -F",
#         NMAP_MODES.FULL: "-sV -sC -A -O",
#         NMAP_MODES.STEALTH: "-sS -sV -T2 -O --script \"default or (discovery and safe)\"",
#     }

#     nmap = nmap3.NmapScanTechniques()

#     def __init__(self, target, mode):
#         self.target = target
#         self.mode : NMAP_MODES = mode
#         self.results = {} 

#     def scan(self):
#         results = self.nmap.nmap_tcp_scan(self.target, args=self.NMAP_COMMANDS[self.mode.value])
#         transformed_results = self._transformOutput(results)

#         return transformed_results
    
#     def _transformOutput(self, output):
#         del output["stats"]
#         del output["runtime"]
#         del output["verbose"]
     
        