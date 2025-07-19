import networkx as nx
import matplotlib.pyplot as plt
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scanners.network_scanner import get_arp_table


def build_network_map():
    arp_data = get_arp_table()
    graph = nx.Graph()

    for line in arp_data.split('\n'):
        if '-' in line:
            parts = line.split()
            if len(parts) >= 2:
                ip, mac = parts[0], parts[1]
                graph.add_node(ip)
                graph.add_edge('localhost', ip)

    nx.draw(graph, with_labels=True)
    plt.title('Network Map')
    plt.show()

if __name__ == "__main__":
    build_network_map()
