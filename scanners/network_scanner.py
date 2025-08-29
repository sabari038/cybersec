import socket
import threading
import subprocess
import psutil

class NetworkScanner:
    def __init__(self, target="127.0.0.1", ports=range(20, 1025), udp_ports=[53, 123, 161]):
        self.target = target
        self.ports = ports
        self.udp_ports = udp_ports
        self.open_ports = []
        self.udp_services = []
        self.banners = {}

    def scan_port(self, port):
        """
        TCP connect scan + banner grab.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                self.open_ports.append(port)
                try:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(1024).decode(errors="ignore").strip()
                    if banner:
                        self.banners[port] = banner.split("\n")[0]
                except Exception:
                    self.banners[port] = "Service detected, no banner"
            sock.close()
        except Exception:
            pass

    def scan_udp(self, port):
        """
        Very simple UDP probe.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            sock.sendto(b"\x00", (self.target, port))
            data, _ = sock.recvfrom(1024)
            self.udp_services.append({port: data.decode(errors="ignore")})
            sock.close()
        except Exception:
            pass

    def get_arp_table(self):
        return subprocess.getoutput("arp -a")

    def get_dns_cache(self):
        return subprocess.getoutput('powershell "Get-DnsClientCache"')

    def get_network_interfaces(self):
        return {nic: addrs[0].address for nic, addrs in psutil.net_if_addrs().items() if addrs}

    def get_network_shares(self):
        return subprocess.getoutput("net share")

    def get_rpc_endpoints(self):
        return subprocess.getoutput('powershell "Get-WmiObject -Namespace root\\cimv2 -Class Win32_Service | Select Name,DisplayName"')

    def scan(self):
        """
        Perform full network scan with system enumeration.
        """
        # TCP Scan
        threads = []
        for port in self.ports:
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

        # UDP Scan
        for port in self.udp_ports:
            self.scan_udp(port)

        return {
            "target": self.target,
            "open_tcp_ports": self.open_ports,
            "tcp_banners": self.banners,
            "open_udp_services": self.udp_services,
            "arp_table": self.get_arp_table(),
            "dns_cache": self.get_dns_cache(),
            "network_interfaces": self.get_network_interfaces(),
            "network_shares": self.get_network_shares(),
            "rpc_endpoints": self.get_rpc_endpoints()
        }
