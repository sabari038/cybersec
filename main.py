from scanners.system_scanner import scan_system
from scanners.network_scanner import scan_network
from report.report_generator import generate_pdf_report
from visualizer.network_mapper import build_network_map

def main():
    print("[*] Scanning system...")
    system_data = scan_system()
    print("[*] Scanning network...")
    network_data = scan_network()

    full_report = {
        'System Information': system_data,
        'Network Information': network_data,
    }

    print("[*] Generating PDF report...")
    generate_pdf_report(full_report)

    print("[*] Building network map...")
    build_network_map()

    print("[+] Scan complete. Report generated as 'vulnerability_report.pdf'.")

if __name__ == "__main__":
    main()
