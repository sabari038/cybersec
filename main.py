from scanners.system_scanner import SystemScanner
from scanners.network_scanner import NetworkScanner
from reports.report_generator import ReportGenerator
from visualizer.network_mapper import build_network_map

def main():
    print("[*] Running system scan...")
    sys_scan = SystemScanner().scan()

    print("[*] Running network scan...")
    net_scan = NetworkScanner(target="127.0.0.1").scan()

    print("[*] Building report...")
    report = ReportGenerator("vulnerability_report.pdf")
    report.add_section("System Information", sys_scan.get("Basic Information"))
    report.add_section("CPU", sys_scan.get("CPU"))
    report.add_section("Memory", sys_scan.get("Memory"))
    report.add_section("Disk", sys_scan.get("Disk"))
    report.add_section("Running Processes", sys_scan.get("Running Processes"))
    report.add_section("Installed Hotfixes", sys_scan.get("Installed Hotfixes"))
    report.add_section(".NET Versions", sys_scan.get(".NET Versions"))
    report.add_section("Antivirus", sys_scan.get("Antivirus"))
    report.add_section("Firewall Status", sys_scan.get("Firewall Status"))
    report.add_section("Users and Groups", sys_scan.get("Users and Groups"))

    report.add_section("Network Scan - TCP", net_scan.get("open_tcp_ports"))
    report.add_section("TCP Banners", net_scan.get("tcp_banners"))
    report.add_section("UDP Services", net_scan.get("open_udp_services"))
    report.add_section("ARP Table", net_scan.get("arp_table"))
    report.add_section("DNS Cache", net_scan.get("dns_cache"))
    report.add_section("Network Interfaces", net_scan.get("network_interfaces"))
    report.add_section("Network Shares", net_scan.get("network_shares"))
    report.add_section("RPC Endpoints", net_scan.get("rpc_endpoints"))

    print("[*] Generating network map...")
    image_path = build_network_map()
    report.add_image(image_path, "Discovered Network Topology")

    report.build()

if __name__ == "__main__":
    main()
