import socket
import nmap
import whois
import requests
import ipinfo
from io import StringIO
import time
from tqdm import tqdm  # Import the tqdm module for the progress bar

def ip_scan(network_prefix):
    active_hosts = []
    nm = nmap.PortScanner()
    scan_result = nm.scan(hosts=network_prefix + ".0/24", arguments="-F -sV")  # Fast scan with service version detection
    for host in scan_result["scan"]:
        if nm[host]["status"]["state"] == "up":
            active_hosts.append(host)
    return active_hosts

def get_whois_info(ip_address):
    try:
        w = whois.whois(ip_address)
        if w.status and w.status.lower() == "ok" and w.nic_irr_id:
            historical_whois = whois.whois("nic.irr.net:" + w.nic_irr_id)
            w.update(historical_whois)
        return w
    except Exception as e:
        return str(e)

def get_ipinfo(ip_address, api_key):
    try:
        handler = ipinfo.getHandler(api_key)
        response = handler.getDetails(ip_address)
        return response.all
    except requests.exceptions.RequestException as e:
        return str(e)

def display_info(title, data):
    print(f"\n{title}")
    for key, value in data.items():
        print(f"{key.capitalize()}: {value}")

if __name__ == "__main__":
    network_prefix = ""  # Replace with the appropriate network prefix you want to scan
    api_key = ""  # Replace with your actual IPinfo API key

    start_time_total = time.time()

    active_hosts = ip_scan(network_prefix)

    print("Active hosts on the network:")
    for host in tqdm(active_hosts, desc="Scanning hosts", unit="host"):
        print(f"\nHost: {host}")
        start_time_host = time.time()
        
        # Reverse DNS lookup
        try:
            hostname = socket.gethostbyaddr(host)[0]
            print(f"Hostname: {hostname}")
        except socket.herror:
            print("Hostname: Not found")

        # WHOIS Information with historical data
        whois_info = get_whois_info(host)
        display_info("Historical WHOIS Information", whois_info)

        # IPinfo Information
        ipinfo_info = get_ipinfo(host, api_key)
        display_info("IPinfo Information", ipinfo_info)
        
        # Open port details
        nm = nmap.PortScanner()
        open_ports = nm.scan(hosts=host, arguments="-p-")["scan"][host]["tcp"].keys()
        print("\nOpen ports:")
        print(", ".join(map(str, open_ports)))

        # Vulnerability scanning
        print("\nVulnerability Scanning:")
        vulnerability_scripts = [
            "http-vuln-cve2021-26855",  # Microsoft Exchange Server ProxyLogon Vulnerability (CVE-2021-26855)
            "http-vuln-cve2021-26858",  # Microsoft Exchange Server Remote Code Execution (CVE-2021-26858)
            "http-vuln-cve2021-27065",  # Microsoft Exchange Server Remote Code Execution (CVE-2021-27065)
            "http-vuln-cve2020-1472",  # Microsoft Netlogon Remote Protocol (Zerologon) Vulnerability (CVE-2020-1472)
            "ssl-heartbleed",  # OpenSSL Heartbleed Vulnerability (CVE-2014-0160)
            "ssl-poodle",  # SSLv3 POODLE Vulnerability (CVE-2014-3566)
            "ssh-vulnkey",  # SSH Weak Key Detection
            "smtp-vuln-cve2010-4344",  # Exim SMTP Server Remote Code Execution (CVE-2010-4344)
            "smb-vuln-ms17-010",  # EternalBlue SMB Vulnerability (MS17-010)
            "smb-vuln-ms08-067",  # SMB Vulnerability (MS08-067)
            # Add more vulnerability scripts as needed
        ]

        for port in open_ports:
            for script in vulnerability_scripts:
                script_result = nm.scan(hosts=host, arguments=f"-p {port} --script {script}")["scan"][host]
                if "script" in script_result and script in script_result["script"]:
                    print(f"Port {port} ({nm[host]['tcp'][int(port)]['name']}): {script_result['script'][script]['output']}")

        print("-" * 30)
        
        end_time_host = time.time()
        print(f"\nTotal time for {host}: {end_time_host - start_time_host:.2f} seconds.")
        print("-" * 30)
    
    end_time_total = time.time()
    print(f"\nTotal time for the entire scan: {end_time_total - start_time_total:.2f} seconds.")
