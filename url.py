import requests
from bs4 import BeautifulSoup
import socket
import netifaces
from ipinfo import getHandler
import whois
from urllib.parse import urlparse
import nmap

# Google Safe Browsing API endpoint
SAFE_BROWSING_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# Google Safe Browsing API key
SAFE_BROWSING_API_KEY = ""

def check_url_safe(url):
    try:
        payload = {
            "client": {
                "clientId": "your-client-id",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {SAFE_BROWSING_API_KEY}"
        }

        response = requests.post(SAFE_BROWSING_API_URL, json=payload, headers=headers)
        response_data = response.json()

        if "matches" in response_data:
            print("URL flagged as potentially harmful by Google Safe Browsing:")
            for match in response_data["matches"]:
                print(f"Threat type: {match['threatType']}")
                print(f"Threat entry: {match['threat']['url']}")
                if "platformType" in match:
                    print(f"Platform type: {match['platformType']}")
                if "threatEntryMetadata" in match:
                    metadata = match["threatEntryMetadata"]["entries"]
                    if metadata:
                        print("Threat entry metadata:")
                        for entry in metadata:
                            print(f"- {entry}")
        else:
            print("URL is safe according to Google Safe Browsing.")
            print("---------------------------------------------------------------")

    except requests.exceptions.RequestException as e:
        print(f"Error checking URL safety: {str(e)}")

def scrape_url(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, "html.parser")
        # Extract desired information from the soup object
        # Example: Retrieve the page title
        title = soup.title.string

        # Example: Extract all paragraph texts
        paragraphs = soup.find_all("p")
        paragraph_texts = [p.text for p in paragraphs]

        # Example: Extract the href attribute from all anchor tags
        anchor_tags = soup.find_all("a")
        hrefs = [a.get("href") for a in anchor_tags]

        return title, paragraph_texts, hrefs
    except requests.exceptions.RequestException as e:
        print(f"Error scraping URL: {str(e)}")
        return None, None, None

def get_ip_from_url(url):
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.gaierror as e:
        print(f"Error resolving IP address for {url}: {str(e)}")
        return None

def get_ip_info(ip_address):
    handler = getHandler()
    details = handler.getDetails(ip_address)
    return details.all

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return w
    except whois.parser.PywhoisError as e:
        print(f"Error retrieving WHOIS information for {domain}: {str(e)}")
        return None

def perform_nmap_scan(target):
    try:
        nm = nmap.PortScanner()
        scan_results = nm.scan(target, arguments="-Pn -sV")

        if scan_results['scan']:
            print(f"\nNmap scan results for {target}:")
            print("Host\t| Port\t| State\t| Service")
            for host, result in scan_results['scan'].items():
                if 'tcp' in result:
                    for port, port_info in result['tcp'].items():
                        print(f"{host}\t| {port}\t| {port_info['state']}\t| {port_info['name']}")
        else:
            print(f"No results found for Nmap scan of {target}")

    except nmap.PortScannerError as e:
        print(f"Error performing Nmap scan: {str(e)}")

# Example usage
url = ""
ip_address = get_ip_from_url(url)
if ip_address:
    print(f"IP address for {url}: {ip_address}")
    print("---------------------------------------------------------------")

    # Check URL safety using Google Safe Browsing API
    check_url_safe(url)

title, paragraphs, hrefs = scrape_url(url)
if title:
    print(f"Title of the page: {title}")
    print("---------------------------------------------------------------")

ip_info = get_ip_info(ip_address)
if ip_info:
    print(f"\nIP Information for {ip_address}:")
    print(ip_info)

domain = ""
whois_info = get_whois_info(domain)
if whois_info:
    print("------------------------------------------------------------------------------------")
    print(f"\nWHOIS Information for {domain}:")
    print(whois_info)
    print("------------------------------------------------------------------------------------")

# Perform Nmap scan on the target IP address
perform_nmap_scan(ip_address)
