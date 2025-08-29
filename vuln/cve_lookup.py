import os
import time
import requests
import nmap  # pip install python-nmap

# NVD CVE API
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _nvd_search(keyword: str, results_per_page: int = 20):
    """
    Query NVD for a keyword and return JSON. Uses API key if present in env.
    """
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": results_per_page,
    }
    headers = {}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.json()


def _extract_cvss(metrics: dict):
    """
    Extract CVSS base score + severity from NVD metrics (prefer v3.1 > v3.0 > v2).
    """
    if not metrics:
        return None, "Unknown"
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            try:
                score = metrics[key][0]["cvssData"]["baseScore"]
                severity = metrics[key][0]["cvssData"]["baseSeverity"]
                return score, severity
            except Exception:
                continue
    return None, "Unknown"


def scan_network_version(target="127.0.0.1", open_ports=None):
    """
    Run nmap with service version detection (-sV).
    If open_ports are provided, only scan those to save time.
    """
    nm = nmap.PortScanner()
    print(f"[+] Running version detection scan on {target} ...")

    # If we already have open ports, scan only those
    if open_ports:
        ports_str = ",".join(str(p) for p in open_ports)
        nm.scan(hosts=target, ports=ports_str, arguments="-sV")
    else:
        # fallback: scan top 1000 ports
        nm.scan(hosts=target, arguments="-sV --top-ports 1000")

    services = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port, service in nm[host][proto].items():
                services.append({
                    "port": port,
                    "protocol": proto,
                    "service": service.get("name", ""),
                    "product": service.get("product", ""),
                    "version": service.get("version", ""),
                    "extrainfo": service.get("extrainfo", "")
                })
    return services


def _build_keywords(system_data: dict, detected_services: list):
    """
    Convert system info + detected services into search keywords for NVD.
    """
    keywords = set()

    # OS info
    try:
        os_name = system_data.get("Basic Info", {}).get("OS")
        os_ver = system_data.get("Basic Info", {}).get("OS Version")
        if os_name:
            keywords.add(os_name)
        if os_name and os_ver:
            keywords.add(f"{os_name} {os_ver}")
    except Exception:
        pass

    # .NET versions
    try:
        for v in system_data.get(".NET Versions", []):
            keywords.add(f".NET Framework {v}")
    except Exception:
        pass

    # Detected services (product + version)
    for svc in detected_services:
        if svc.get("product"):
            if svc.get("version"):
                keywords.add(f"{svc['product']} {svc['version']}")
            else:
                keywords.add(svc["product"])
        elif svc.get("service"):
            keywords.add(svc["service"])

    return list(keywords)


def find_relevant_cves(system_data: dict, target="127.0.0.1", open_ports=None, max_per_query: int = 20, polite_delay_sec: float = 1.2):
    """
    Full CVE lookup workflow:
    1. Run version scan on open ports
    2. Build search keywords
    3. Query NVD for CVEs
    4. Return results sorted by severity
    """
    detected_services = scan_network_version(target, open_ports=open_ports)
    queries = _build_keywords(system_data, detected_services)

    results = []
    seen_ids = set()

    for q in queries:
        try:
            data = _nvd_search(q, results_per_page=max_per_query)
            vulns = data.get("vulnerabilities", [])
            for v in vulns:
                cve = v.get("cve", {})
                cve_id = cve.get("id")
                if not cve_id or cve_id in seen_ids:
                    continue

                # Pick English description
                desc = ""
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value", "")
                        break

                score, severity = _extract_cvss(cve.get("metrics", {}))
                results.append({
                    "cve": cve_id,
                    "cvss": score,
                    "severity": severity,
                    "matched_on": q,
                    "description": desc[:300]  # trim for readability
                })
                seen_ids.add(cve_id)

        except Exception as e:
            results.append({"error": f'Lookup failed for "{q}": {e}'})

        # Respect NVD rate limits
        time.sleep(polite_delay_sec)

    # Sort by severity (Critical > High > Medium > Low > Unknown) and CVSS score
    severity_order = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "Unknown": 5}
    results.sort(key=lambda r: (
        severity_order.get(r.get("severity", "Unknown"), 5),
        -(r.get("cvss") or 0)
    ))

    return {
        "target": target,
        "queries": queries,
        "matches": results[:100],  # cap results for readability
        "services": detected_services
    }
