import argparse
import socket
import psutil
import hashlib
import os
import requests

# ===============================
# 🔍 VULNERABILITY SCANNER
# ===============================
def scan_ports(target="127.0.0.1"):
    ports = [21, 22, 23, 80, 443]
    open_ports = []

    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        if sock.connect_ex((target, port)) == 0:
            open_ports.append(port)

        sock.close()

    return open_ports


def vulnerability_scanner():
    ports = scan_ports()
    risk = "HIGH" if 23 in ports else "MODERATE"

    return {
        "module": "Vulnerability Scanner",
        "open_ports": ports,
        "risk": risk
    }


# ===============================
# 🌐 NETWORK ANALYZER
# ===============================
def network_analyzer():
    connections = []

    for conn in psutil.net_connections():
        if conn.status == "ESTABLISHED":
            connections.append({
                "local": str(conn.laddr),
                "remote": str(conn.raddr)
            })

    return {
        "module": "Network Analyzer",
        "connections": connections
    }


# ===============================
# 🧠 THREAT HUNTING
# ===============================
SUSPICIOUS_KEYWORDS = ["keylogger", "malware", "trojan"]

def threat_hunter():
    suspicious = []

    for proc in psutil.process_iter(['pid', 'name']):
        name = (proc.info['name'] or "").lower()

        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in name:
                suspicious.append(proc.info)

    return {
        "module": "Threat Hunting",
        "suspicious_processes": suspicious
    }


# ===============================
# 📁 FILE INTEGRITY
# ===============================
def hash_file(filepath):
    with open(filepath, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def file_integrity(folder="."):
    baseline = {}

    for file in os.listdir(folder):
        path = os.path.join(folder, file)

        if os.path.isfile(path):
            try:
                baseline[file] = hash_file(path)
            except:
                pass

    return {
        "module": "File Integrity",
        "baseline": baseline
    }


# ===============================
# 🌍 OSINT MODULE
# ===============================
def osint(domain):
    try:
        ip = socket.gethostbyname(domain)
        headers = requests.get("http://" + domain, timeout=3).headers

        return {
            "module": "OSINT",
            "domain": domain,
            "ip": ip,
            "headers": dict(headers)
        }

    except Exception as e:
        return {
            "module": "OSINT",
            "error": str(e)
        }


# ===============================
# 🔧 HARDENING CHECK
# ===============================
def hardening():
    file = __file__
    permissions = oct(os.stat(file).st_mode)[-3:]

    return {
        "module": "Hardening",
        "permissions": permissions,
        "recommendation": "Restrict permissions if too open"
    }


# ===============================
# 📊 OUTPUT FORMATTER
# ===============================
def pretty_print(result):
    print("\n==============================")
    print(f"📌 {result['module']}")
    print("==============================")

    for key, value in result.items():
        if key != "module":
            print(f"{key}: {value}")


# ===============================
# 🚀 MAIN CONTROLLER
# ===============================
def main():
    parser = argparse.ArgumentParser(description="Threat Sentinel Pro - All-in-One Cybersecurity Toolkit")

    parser.add_argument("--vuln", action="store_true", help="Run Vulnerability Scanner")
    parser.add_argument("--network", action="store_true", help="Run Network Analyzer")
    parser.add_argument("--threat", action="store_true", help="Run Threat Hunting")
    parser.add_argument("--integrity", action="store_true", help="Run File Integrity Check")
    parser.add_argument("--osint", type=str, help="Run OSINT on domain")
    parser.add_argument("--harden", action="store_true", help="Run Hardening Check")

    args = parser.parse_args()

    if args.vuln:
        pretty_print(vulnerability_scanner())

    if args.network:
        pretty_print(network_analyzer())

    if args.threat:
        pretty_print(threat_hunter())

    if args.integrity:
        pretty_print(file_integrity())

    if args.osint:
        pretty_print(osint(args.osint))

    if args.harden:
        pretty_print(hardening())


if __name__ == "__main__":
    main()