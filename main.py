from scanners.system_scanner import scan_system
from scanners.network_scanner import scan_network
from report.report_generator import generate_pdf_report
from visualizer.network_mapper import build_network_map
from vuln.cve_lookup import find_relevant_cves   # NEW


def main():
    print("[*] Scanning system...")
    system_data = scan_system()

    print("[*] Scanning network...")
    network_data = scan_network()

    print("[*] Looking up CVEs in NVD...")
    # Pass IP + open ports to avoid full scan (faster)
    cve_data = find_relevant_cves(
        system_data,
        target="127.0.0.1",   # Change to another host if needed
        open_ports=network_data.get("Open Ports", []),
        max_per_query=3
    )

    full_report = {
        'System Information': system_data,
        'Network Information': network_data,
        'Potential Vulnerabilities (NVD)': cve_data,   # NEW in report
    }

    print("[*] Generating PDF report...")
    generate_pdf_report(full_report)

    print("[*] Building network map...")
    build_network_map()

    print("[+] Scan complete. Report generated as 'vulnerability_report.pdf'.")


if __name__ == "__main__":
    main()
