import socket
import ipaddress
import concurrent.futures
import networkx as nx
import os

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

def ping_ip(ip):
    result = os.system(f"ping -n 1 -w 500 {ip} >nul 2>&1")
    return ip if result == 0 else None

def build_topology():
    local_ip = get_local_ip()
    network = ipaddress.IPv4Network(local_ip + '/24', strict=False)

    reachable_ips = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(ping_ip, str(ip)): ip for ip in network.hosts()}
        for future in concurrent.futures.as_completed(futures):
            ip = future.result()
            if ip:
                reachable_ips.append(ip)

    # Build the graph
    G = nx.Graph()
    for ip in reachable_ips:
        G.add_node(ip)

    # For simplicity, connect all detected devices to the local IP
    for ip in reachable_ips:
        if ip != local_ip:
            G.add_edge(local_ip, ip)

    return G
