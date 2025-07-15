import nmap
import ssl
import ipaddress
import requests
import subprocess
import concurrent.futures
import xml.etree.ElementTree as ET
from typing import List, Dict, Any
from colorama import Fore, Style, init
import argparse
import sys
from fpdf import FPDF
import platform
import sys
from rich import print
from rich.prompt import Prompt
from datetime import datetime
init(autoreset=True)

# --- CONFIG ---
API_KEY = "OZ26D1CUUXT4QV75BKYKM77CNK3CWYFKCKLFBASAZDHIDKM86Y64L2GDLBPRUDMZ"
DEFAULT_SUBNET = "192.168.1.0/24"
PORT_RANGE = "1-1024"













def get_package_manager():
    os_name = platform.system()

    if os_name == "Linux":
        try:
            with open("/etc/os-release") as f:
                os_release = f.read().lower()
        except FileNotFoundError:
            os_release = ""

        if "ubuntu" in os_release or "debian" in os_release:
            return os_name, "debian/ubuntu", "apt"
        elif "fedora" in os_release or "red hat" in os_release or "centos" in os_release:
            return os_name, "fedora/centos/rhel", "dnf"
        elif "arch" in os_release:
            return os_name, "arch", "pacman"
        elif "opensuse" in os_release:
            return os_name, "opensuse", "zypper"
        else:
            for pm in ["apt", "dnf", "yum", "pacman", "zypper"]:
                if subprocess.run(["which", pm], capture_output=True).returncode == 0:
                    return os_name, "linux-unknown", pm
            return os_name, "linux-unknown", None

    elif os_name == "Darwin":
        return os_name, "macos", "brew"
    elif os_name == "Windows":
        for pm in ["winget", "choco"]:
            if subprocess.run(["where", pm], capture_output=True, shell=True).returncode == 0:
                return os_name, "windows", pm
        return os_name, "windows", None
    else:
        return os_name, None, None


def install_package(package_name):
    os_name, distro, pm = get_package_manager()

    if pm is None:
        raise EnvironmentError(f"Package manager non trovato per sistema {os_name} / {distro}")

    if pm == "apt":
        subprocess.run(["sudo", "apt", "update"], check=True)
        cmd = ["sudo", "apt", "install", "-y", package_name]
    elif pm == "dnf":
        cmd = ["sudo", "dnf", "install", "-y", package_name]
    elif pm == "yum":
        cmd = ["sudo", "yum", "install", "-y", package_name]
    elif pm == "pacman":
        cmd = ["sudo", "pacman", "-Sy", package_name]
    elif pm == "zypper":
        cmd = ["sudo", "zypper", "install", "-y", package_name]
    elif pm == "brew":
        cmd = ["brew", "install", package_name]
    elif pm == "winget":
        cmd = ["winget", "install", "--id", package_name]
    elif pm == "choco":
        cmd = ["choco", "install", package_name, "-y"]
    else:
        raise EnvironmentError(f"Package manager {pm} non supportato")

    print(f"[bold green]Eseguo il comando:[/bold green] {' '.join(cmd)}")
    subprocess.run(cmd, check=True)


def check_nmap():
    if subprocess.run(["which", "nmap"], capture_output=True).returncode != 0:
        print("[bold red]⚠️ Nmap non risulta installato sul sistema.[/bold red]")
        risposta = Prompt.ask("[bold yellow]Vuoi installarlo ora?[/bold yellow] (S/n)", default="S")
        if risposta.lower() in ["s", "si", "y", "yes"]:
            install_package("nmap")
        else:
            print("[bold red]Nmap è necessario per continuare. Uscita...[/bold red]")
            sys.exit(0)
    else:
        print("[bold green]✅ Nmap è già installato.[/bold green]")


def check_dependency(command_name, package_name=None, is_python_package=False):
    if subprocess.run(["which", command_name], capture_output=True).returncode != 0:
        print(f"[bold red]⚠️ {command_name} non risulta installato sul sistema.[/bold red]")
        risposta = Prompt.ask(f"[bold yellow]Vuoi installare {package_name or command_name} ora?[/bold yellow] (S/n)", default="S")
        if risposta.lower() in ["s", "si", "y", "yes"]:
            install_package(package_name or command_name, is_python_package=is_python_package)
        else:
            print(f"[bold red]{command_name} è necessario per continuare. Uscita...[/bold red]")
            sys.exit(0)
    else:
        print(f"[bold green]✅ {command_name} è già installato.[/bold green]")



# --- Funzione classificazione severità ---
def classify_severity(score: float) -> str:
    if score >= 9.0:
        return Fore.RED + "CRITICAL" + Style.RESET_ALL
    elif score >= 7.0:
        return Fore.MAGENTA + "HIGH" + Style.RESET_ALL
    elif score >= 4.0:
        return Fore.YELLOW + "MEDIUM" + Style.RESET_ALL
    else:
        return Fore.CYAN + "LOW" + Style.RESET_ALL

# --- Scansione host e porte con sudo nmap ---
def scan_host_ports(host: str, ports: str = PORT_RANGE) -> Dict[str, Any]:
    print(Fore.BLUE + f"[*] Scanning ports on host {host} with sudo nmap..." + Style.RESET_ALL)
    try:
        cmd = ['sudo', 'nmap', '-sS', '-sV', '-p', ports, '-T4', '--host-timeout', '30s', '--max-retries', '1', '-oX', '-', host]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.stderr:
            print(Fore.RED + f"[ERROR] Nmap scan stderr: {result.stderr}" + Style.RESET_ALL)

        xml_output = result.stdout
        if not xml_output.strip():
            print(Fore.YELLOW + f"[WARN] Empty scan result for host {host}" + Style.RESET_ALL)
            return {}

        services = []
        root = ET.fromstring(xml_output)
        for host_elem in root.findall('host'):
            addr_elem = host_elem.find('address')
            host_ip = addr_elem.get('addr') if addr_elem is not None else host

            ports_elem = host_elem.find('ports')
            if ports_elem is None:
                continue

            for port_elem in ports_elem.findall('port'):
                port_id = port_elem.get('portid')
                protocol = port_elem.get('protocol')
                state_elem = port_elem.find('state')
                service_elem = port_elem.find('service')

                services.append({
                    "port": int(port_id),
                    "protocol": protocol,
                    "state": state_elem.get('state') if state_elem is not None else "",
                    "name": service_elem.get('name') if service_elem is not None else "",
                    "product": service_elem.get('product') if service_elem is not None else "",
                    "version": service_elem.get('version') if service_elem is not None else "",
                    "extrainfo": service_elem.get('extrainfo') if service_elem is not None else ""
                })

        return {"host": host, "services": services}
    except Exception as e:
        print(Fore.RED + f"[ERROR] Nmap subprocess scan failed: {e}" + Style.RESET_ALL)
        return {}

# --- Discovery hosts attivi nella subnet ---
def discover_hosts(subnet: str) -> List[str]:
    nm = nmap.PortScanner()
    print(Fore.GREEN + f"[*] Discovering hosts in subnet {subnet} ..." + Style.RESET_ALL)
    try:
        nm.scan(hosts=subnet, arguments='-sn -T4 --host-timeout 30s --max-retries 1')
    except Exception as e:
        print(Fore.RED + f"[ERROR] Nmap discovery scan failed: {e}" + Style.RESET_ALL)
        return []
    hosts_up = nm.all_hosts()
    print(Fore.GREEN + f"[+] Hosts found: {hosts_up}" + Style.RESET_ALL)
    return hosts_up

# --- API Vulners per CVE ---
def get_cve_for_service(product: str, version: str) -> List[Dict[str, Any]]:
    query = f"{product} {version}"
    url = "https://vulners.com/api/v3/search/lucene/"
    payload = {"query": query, "size": 10}
    headers = {"Content-Type": "application/json", "X-Api-Key": API_KEY}
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        if data.get("result") != "OK":
            print(Fore.YELLOW + f"[WARN] Vulners API returned non-OK result for {query}" + Style.RESET_ALL)
            return []
        cves = []
        for item in data.get("data", {}).get("documents", []):
            cve_id = item.get("title", "Unknown")
            if "CVE-" in cve_id:
                severity_score = item.get("cvss", {}).get("score", 0.0)
                cves.append({
                    "cve_id": cve_id,
                    "type": item.get("type", "Unknown"),
                    "severity_score": severity_score,
                    "description": item.get("description", ""),
                    "link": item.get("href", "")
                })
        return cves
    except Exception as e:
        print(Fore.RED + f"[ERROR] Vulners API request failed: {e}" + Style.RESET_ALL)
        return []

# --- Controlli modulari ---
def controllo_cve(host: str, port: int, svc: Dict[str, Any]) -> List[str]:
    product = svc.get("product", "")
    version = svc.get("version", "")
    issues = []
    if product and version:
        cves = get_cve_for_service(product, version)
        if cves:
            for cve in cves:
                sev_label = classify_severity(cve["severity_score"])
                issues.append(f"{sev_label} {cve['cve_id']} - {cve['description']}")
        else:
            issues.append("No known CVEs found.")
    else:
        issues.append("Product/version info missing for CVE check.")
    return issues

def controllo_http_headers(host: str, port: int, svc: Dict[str, Any]) -> List[str]:
    issues = []
    if svc.get("name") in ["http", "https"]:
        try:
            protocol = "https" if svc.get("name") == "https" else "http"
            url = f"{protocol}://{host}:{port}"
            response = requests.head(url, timeout=5)
            headers = response.headers
            if "Server" not in headers:
                issues.append("Missing Server HTTP header")
            if "X-Powered-By" in headers:
                issues.append("X-Powered-By header found - possible information leak")
            if "Content-Security-Policy" not in headers:
                issues.append("Missing Content-Security-Policy header")
            if "Strict-Transport-Security" not in headers and protocol == "https":
                issues.append("Missing HSTS header on HTTPS service")
        except Exception as e:
            issues.append(f"HTTP header check failed: {e}")
    return issues

def controllo_ssl_expiry(host: str, port: int, svc: Dict[str, Any]) -> List[str]:
    issues = []
    if svc.get("name") == "https":
        context = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        expires = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        days_left = (expires - datetime.utcnow()).days
                        if days_left < 30:
                            issues.append(f"SSL certificate expiring soon ({days_left} days left)")
        except Exception as e:
            issues.append(f"SSL expiry check failed: {e}")
    return issues

def controllo_common_admin_paths(host: str, port: int, svc: Dict[str, Any]) -> List[str]:
    issues = []
    if svc.get("name") in ["http", "https"]:
        protocol = "https" if svc.get("name") == "https" else "http"
        urls = ["/admin", "/login", "/test", "/phpmyadmin"]
        for path in urls:
            try:
                url = f"{protocol}://{host}:{port}{path}"
                r = requests.get(url, timeout=3)
                if r.status_code < 400:
                    issues.append(f"Accessible common path: {path} (status {r.status_code})")
            except:
                pass
    return issues

def controllo_reverse_dns(host: str, port: int, svc: Dict[str, Any]) -> List[str]:
    issues = []
    try:
        rev = socket.gethostbyaddr(host)
        issues.append(f"Reverse DNS: {rev[0]}")
    except:
        issues.append("No reverse DNS configured")
    return issues

def controllo_ssh_protocol_v1(host: str, port: int, svc: dict) -> list:
    issues = []
    if svc.get("name") == "ssh":
        try:
            # Il banner SSH contiene la versione del protocollo
            with socket.create_connection((host, port), timeout=5) as sock:
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                if "SSH-1." in banner:
                    issues.append("SSH protocol v1 detected - vulnerable and deprecated")
        except Exception as e:
            issues.append(f"SSH protocol check failed: {e}")
    return issues

from ftplib import FTP, error_perm

def controllo_ftp_anonymous_upload(host: str, port: int, svc: dict) -> list:
    issues = []
    if svc.get("name") == "ftp":
        try:
            ftp = FTP()
            ftp.connect(host, port, timeout=5)
            ftp.login()  # anonymous login
            try:
                # Provo a scrivere un file di prova in /tmp o root
                test_file = "test_upload.txt"
                ftp.storbinary(f"STOR {test_file}", open("/dev/null", "rb"))
                issues.append("FTP anonymous upload allowed - critical vulnerability")
            except error_perm:
                pass  # upload non permesso, bene
            ftp.quit()
        except Exception as e:
            issues.append(f"FTP check failed: {e}")
    return issues

def controllo_http_directory_traversal(host: str, port: int, svc: dict) -> list:
    issues = []
    if svc.get("name") in ["http", "https"]:
        protocol = "https" if svc.get("name") == "https" else "http"
        try:
            url = f"{protocol}://{host}:{port}/../../../../../../../../etc/passwd"
            r = requests.get(url, timeout=5, verify=False)
            if r.status_code == 200 and "root:" in r.text:
                issues.append("Directory Traversal vulnerability detected - /etc/passwd accessible")
        except Exception as e:
            issues.append(f"HTTP Directory Traversal check failed: {e}")
    return issues

def controllo_redis_open(host: str, port: int, svc: dict) -> list:
    issues = []
    if svc.get("name") == "redis":
        try:
            s = socket.socket()
            s.settimeout(3)
            s.connect((host, port))
            s.send(b"PING\r\n")
            res = s.recv(1024)
            if b"+PONG" in res:
                issues.append("Redis server without authentication - critical risk")
            s.close()
        except Exception as e:
            issues.append(f"Redis check failed: {e}")
    return issues

import mysql.connector
from mysql.connector import errors

def controllo_mysql_default_creds(host: str, port: int, svc: dict) -> list:
    issues = []
    if svc.get("name") == "mysql":
        try:
            conn = mysql.connector.connect(
                host=host,
                port=port,
                user="root",
                password="root",
                connection_timeout=5,
            )
            if conn.is_connected():
                issues.append("MySQL default credentials root:root valid - critical")
                conn.close()
        except errors.InterfaceError:
            pass  # non connesso
        except errors.ProgrammingError:
            pass  # credenziali errate
        except Exception as e:
            issues.append(f"MySQL check error: {e}")
    return issues

def controllo_smbv1(host: str, port: int, svc: dict) -> list:
    issues = []
    if svc.get("name") == "microsoft-ds" or port == 445:
        try:
            s = socket.socket()
            s.settimeout(3)
            s.connect((host, port))
            # Pacchetto semplice per query SMB protocol v1
            s.send(b"\x00\x00\x00\x90\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
            res = s.recv(1024)
            if b"SMB" in res and res[4] == 0x72:
                # Versione SMB 1.0
                issues.append("SMB v1 protocol detected - vulnerable to multiple exploits")
            s.close()
        except Exception as e:
            issues.append(f"SMBv1 check failed: {e}")
    return issues

def controllo_porta_sospetta(host: str, port: int, svc: Dict[str, Any]) -> List[str]:
    suspicious_ports = [21, 23, 69, 2323]  # ftp, telnet, tftp, etc.
    issues = []
    if port in suspicious_ports and svc.get("state") == "open":
        issues.append(f"Porta sospetta aperta: {port}")
    return issues

def controllo_banner_grabbing(host: str, port: int, svc: Dict[str, Any]) -> List[str]:
    issues = []
    banner_info = svc.get("extrainfo", "") or svc.get("product", "") or svc.get("version", "")
    if banner_info and ("beta" in banner_info.lower() or "test" in banner_info.lower()):
        issues.append("Banner info reveals beta/test version, potenzialmente insicuro")
    return issues

def controllo_ssh_protocol_version(host: str, port: int, svc: Dict[str, Any]) -> List[str]:
    issues = []
    if svc.get("name") == "ssh" and svc.get("state") == "open":
        version = svc.get("version", "")
        if version and ("1." in version):
            issues.append("SSH protocol version 1 detected, obsoleto e insicuro")
    return issues

def controllo_default_credenziali(host: str, port: int, svc: Dict[str, Any]) -> List[str]:
    issues = []
    admin_ports = [80, 443, 8080, 8443]
    if port in admin_ports and svc.get("state") == "open":
        issues.append("Possibile porta admin aperta, verifica credenziali di default")
    return issues

def controllo_tls_weak_ciphers(host: str, port: int, svc: Dict[str, Any]) -> List[str]:
    issues = []
    if svc.get("name") == "https":
        issues.append("Potenziale TLS con cifratura debole (check approfondito necessario)")
    return issues

def controllo_ftp_anonymous(host: str, port: int, svc: Dict[str, Any]) -> List[str]:
    issues = []
    if svc.get("name") == "ftp" and svc.get("state") == "open":
        issues.append("FTP aperto - verificare login anonimo")
    return issues

def controllo_http_methods(host: str, port: int, svc: Dict[str, Any]) -> List[str]:
    issues = []
    if svc.get("name") in ["http", "https"]:
        try:
            protocol = "https" if svc.get("name") == "https" else "http"
            url = f"{protocol}://{host}:{port}"
            response = requests.options(url, timeout=5)
            allowed_methods = response.headers.get('Allow', '')
            for bad_method in ["DELETE", "TRACE", "PUT"]:
                if bad_method in allowed_methods:
                    issues.append(f"HTTP method {bad_method} abilitato - potenziale vulnerabilità")
        except Exception as e:
            issues.append(f"HTTP methods check failed: {e}")
    return issues



# Lista controlli da eseguire in sequenza
controlli = [
    controllo_cve,
    controllo_http_headers,
    controllo_http_methods,
    controllo_porta_sospetta,
    controllo_banner_grabbing,
    controllo_ssh_protocol_version,
    controllo_default_credenziali,
    controllo_tls_weak_ciphers,
    controllo_ftp_anonymous,
    controllo_ssh_protocol_v1,
    controllo_ftp_anonymous_upload,
    controllo_http_directory_traversal,
    controllo_smbv1,
    controllo_mysql_default_creds,
    controllo_redis_open,
    controllo_ssl_expiry,
    controllo_common_admin_paths,
    controllo_reverse_dns,
]

# --- Report e stampa ---
def print_report(scan_result: Dict[str, Any]):
    host = scan_result.get("host", "Unknown")
    services = scan_result.get("services", [])
    print(Fore.CYAN + f"\n[***] Scan Report for host: {host}" + Style.RESET_ALL)
    if not services:
        print(Fore.YELLOW + "No services found or host down." + Style.RESET_ALL)
        return
    for svc in services:
        port = svc.get("port")
        name = svc.get("name")
        state = svc.get("state")
        product = svc.get("product")
        version = svc.get("version")
        print(f"\nPort: {port} / Service: {name} / State: {state}")
        print(f"Product: {product} / Version: {version}")
        all_issues = []
        for controllo in controlli:
            try:
                issues = controllo(host, port, svc)
                all_issues.extend(issues)
            except Exception as e:
                print(Fore.RED + f"[ERROR] Controllo {controllo.__name__} fallito: {e}" + Style.RESET_ALL)
        if all_issues:
            print(Fore.RED + "[!] Issues found:")
            for issue in all_issues:
                print(f"  - {issue}")
            print(Style.RESET_ALL)
        else:
            print(Fore.GREEN + "No issues found on this service." + Style.RESET_ALL)


def export_report_to_pdf(scan_results: List[Dict[str, Any]], filename: str = "scan_report.pdf"):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)

    # --- Cover page ---
    pdf.add_page()
    pdf.set_font("Arial", 'B', 20)
    pdf.cell(0, 10, "Network Scan Report", 0, 1, 'C')
    pdf.set_font("Arial", '', 14)
    pdf.cell(0, 10, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1, 'C')
    pdf.ln(10)

    # --- Summary ---
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(0, 10, "Summary", 0, 1)
    pdf.set_font("Arial", '', 12)
    for scan_result in scan_results:
        host = scan_result.get("host", "Unknown")
        services = scan_result.get("services", [])
        total_issues = 0
        for svc in services:
            for controllo in controlli:
                issues = controllo(host, svc.get("port"), svc)
                total_issues += len(issues)
        pdf.cell(0, 8, f"{host}: {total_issues} issues found", 0, 1)
    pdf.add_page()

    # --- Detailed report per host ---
    for scan_result in scan_results:
        host = scan_result.get("host", "Unknown")
        services = scan_result.get("services", [])

        pdf.set_font("Arial", 'B', 16)
        pdf.cell(0, 10, f"Host: {host}", 0, 1)
        pdf.set_font("Arial", '', 12)

        if not services:
            pdf.set_text_color(128, 0, 0)
            pdf.cell(0, 10, "No services found or host down.", 0, 1)
            pdf.set_text_color(0, 0, 0)
        else:
            for svc in services:
                port = svc.get("port")
                name = svc.get("name")
                state = svc.get("state")
                product = svc.get("product")
                version = svc.get("version")
                pdf.cell(0, 8, f"Port: {port} / Service: {name} / State: {state}", 0, 1)
                pdf.cell(0, 8, f"Product: {product} / Version: {version}", 0, 1)
                all_issues = []
                for controllo in controlli:
                    try:
                        issues = controllo(host, port, svc)
                        all_issues.extend(issues)
                    except Exception as e:
                        all_issues.append(f"Errore controllo {controllo.__name__}: {e}")
                if all_issues:
                    pdf.set_text_color(255, 0, 0)
                    pdf.cell(0, 8, "[!] Issues found:", 0, 1)
                    for issue in all_issues:
                        pdf.multi_cell(0, 7, f" - {issue}")
                    pdf.set_text_color(0, 0, 0)
                else:
                    pdf.set_text_color(0, 128, 0)
                    pdf.cell(0, 8, "No issues found on this service.", 0, 1)
                    pdf.set_text_color(0, 0, 0)
                pdf.ln(3)
        pdf.add_page()

    pdf.output(filename)
    print(Fore.GREEN + f"[+] Report exported to PDF: {filename}" + Style.RESET_ALL)


def main():
     # Controlla pacman e installa mysql client (mariadb-libs)
    check_dependency("mysql", "mariadb-libs")

    # Controlla modulo python mysql-connector-python
    try:
        import mysql.connector
        print("[bold green]✅ mysql-connector-python è già installato.[/bold green]")
    except ImportError:
        risposta = Prompt.ask("[bold yellow]Vuoi installare mysql-connector-python (modulo Python) ora?[/bold yellow] (S/n)", default="S")
        if risposta.lower() in ["s", "si", "y", "yes"]:
            install_package("mysql-connector-python", is_python_package=True)
        else:
            print("[bold red]mysql-connector-python è necessario per continuare. Uscita...[/bold red]")
            sys.exit(0)


            
    parser = argparse.ArgumentParser(description="Advanced Network Scanner & Vulnerability Checker")
    parser.add_argument('-l', '--list', nargs='+', help="List of IP addresses or hostnames to scan directly")
    parser.add_argument('-f', '--file', help="File containing list of IP addresses or hostnames to scan")
    parser.add_argument('-s', '--subnet', help="Subnet to scan if no list or file provided", default=DEFAULT_SUBNET)
    args = parser.parse_args()

    if args.file:
        try:
            with open(args.file, 'r') as f:
                target_hosts = [line.strip() for line in f if line.strip()]
            print(Fore.GREEN + f"[+] Loaded hosts from file: {target_hosts}" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[!] Error reading file {args.file}: {e}" + Style.RESET_ALL)
            sys.exit(1)
    elif args.list:
        target_hosts = args.list
        print(Fore.GREEN + f"[+] Using provided host list: {target_hosts}" + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + f"[i] No hosts list or file provided, scanning subnet {args.subnet}" + Style.RESET_ALL)
        target_hosts = discover_hosts(args.subnet)

    if not target_hosts:
        print(Fore.RED + "[!] No hosts to scan. Exiting." + Style.RESET_ALL)
        sys.exit(1)

    def process_host(host):
        return scan_host_ports(host)
    
    scan_results = []


    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(process_host, host): host for host in target_hosts}
        for future in concurrent.futures.as_completed(futures):
            host = futures[future]
            try:
                scan_result = future.result()
                print_report(scan_result)
                scan_results.append(scan_result)

            except Exception as e:
                print(Fore.RED + f"[ERROR] Scanning host {host} failed: {e}" + Style.RESET_ALL)
            
        export_report_to_pdf(scan_results)

if __name__ == "__main__":
    print(get_package_manager())
    check_nmap()
    main()
