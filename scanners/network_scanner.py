import psutil
import socket
import subprocess

def get_open_ports():
    connections = psutil.net_connections()
    ports = []
    for conn in connections:
        if conn.status == 'LISTEN':
            ports.append(conn.laddr.port)
    return ports

def get_arp_table():
    output = subprocess.getoutput("arp -a")
    return output

def get_dns_cache():
    cmd = 'powershell "Get-DnsClientCache"'
    output = subprocess.getoutput(cmd)
    return output

def get_tcp_udp_connections():
    return [(conn.laddr, conn.raddr, conn.status) for conn in psutil.net_connections() if conn.raddr]

def scan_network():
    return {
        'Open Ports': get_open_ports(),
        'ARP Table': get_arp_table(),
        'DNS Cache': get_dns_cache(),
        'Connections': get_tcp_udp_connections(),
    }

if __name__ == "__main__":
    import pprint
    pprint.pprint(scan_network())
