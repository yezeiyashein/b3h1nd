import re
import requests
import subprocess
import sys
import pyfiglet
from shodan import Shodan
from prettytable import PrettyTable
from colorama import Fore, init
import argparse

# Initialize colorama
init(autoreset=True)

def print_banner():
    tool_name = pyfiglet.figlet_format("B3H1ND", font="slant") 
    print(Fore.GREEN + tool_name)
    print(Fore.YELLOW + "[*] Version: 1.0.0")
    print(Fore.YELLOW + "[*] Purpose: Scan IPs behind the WAF")
    print(Fore.RED + "[*] Author: N4RG4")
    print(Fore.WHITE + "[*] Run the tool with: python b3h1nd.py <DOMAIN>")
    print(Fore.RED + "----------------------------------------------------")
    print(Fore.WHITE + "Starting the scan...")

# Configuration
SHODAN_API_KEY = "<Your API Key>"
VT_API_KEY = "<Your API Key>"
ALIENVAULT_URL = "https://otx.alienvault.com/api/v1/indicators/hostname/"
URLSCAN_URL = "https://urlscan.io/api/v1/search/"
OUTPUT_FILE = "ip_list.txt"
WEB_SERVERS_FILE = "web_servers.txt"

def is_ipv4(ip):
    ipv4_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    return ipv4_pattern.match(ip) is not None

def check_waf(domain):
    print(f"[*] Checking if {domain} is behind a WAF...")
    try:
        result = subprocess.run(
            ["wafw00f", domain],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            if "[+] The site" in result.stdout:
                waf_name = result.stdout.split("[+] The site")[1].split("is behind")[1].split("\n")[0].strip()
                print(f"[+] The site {domain} is behind {waf_name}")
            else:
                print("[!] No WAF detected.")
        else:
            print(f"[!] Error running wafw00f: {result.stderr}")
    except Exception as e:
        print(f"[!] Error with WAF detection: {e}")

def get_shodan_ips(domain):
    print("[*] Fetching IPs from Shodan...")
    api = Shodan(SHODAN_API_KEY)
    try:
        results = api.search(f"Ssl.cert.subject.CN:{domain}", page=1)
        ips = {match['ip_str'] for match in results['matches'] if is_ipv4(match['ip_str'])}
        return ips
    except Exception as e:
        print(f"[!] Shodan error: {e}")
        return set()

def get_virustotal_ips(domain):
    print("[*] Fetching IPs from VirusTotal...")
    url = f"https://www.virustotal.com/vtapi/v2/domain/report?apikey={VT_API_KEY}&domain={domain}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        resolutions = data.get("resolutions", [])
        ips = {entry["ip_address"] for entry in resolutions if "ip_address" in entry and is_ipv4(entry["ip_address"])}
        return ips
    except Exception as e:
        print(f"[!] VirusTotal error: {e}")
        return set()

def get_alienvault_ips(domain):
    print("[*] Fetching IPs from AlienVault...")
    url = f"{ALIENVAULT_URL}{domain}/url_list?limit=500&page=1"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        ips = {item["result"]["urlworker"]["ip"] for item in data.get("url_list", []) 
               if item.get("result") and item["result"].get("urlworker") and is_ipv4(item["result"]["urlworker"]["ip"])}
        return ips
    except Exception as e:
        print(f"[!] AlienVault error: {e}")
        return set()

def get_urlscan_ips(domain):
    print("[*] Fetching IPs from URLScan.io...")
    url = f"{URLSCAN_URL}?q=domain:{domain}&size=10000"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        ips = {result["page"]["ip"] for result in data.get("results", []) 
               if result.get("page") and is_ipv4(result["page"]["ip"])}
        return ips
    except Exception as e:
        print(f"[!] URLScan.io error: {e}")
        return set()

def check_web_servers(ip_list):
    print("[*] Checking which IPs are running web servers...")
    try:
        result = subprocess.run(
            "cat ip_list.txt | httpx-toolkit -sc -td -title -server",
            shell=True,
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            print(f"[!] Error with httpx-toolkit: {result.stderr}")
            return
        web_servers = [
            line for line in result.stdout.splitlines()
            if "403" not in line and ("200" in line or "301" in line or "302" in line)
        ]
        if not web_servers:
            print("[*] No web servers found.")
        else:
            table = PrettyTable()
            table.field_names = ["IP Address", "HTTP Status", "Title/Server"]
            table.align["IP Address"] = "l"
            table.align["Title/Server"] = "l"
            for server in web_servers:
                parts = server.split(" ")
                ip = parts[0]
                status_code = parts[1]
                title_server = " ".join(parts[2:])
                table.add_row([ip, status_code, title_server])
            print(table)
            with open(WEB_SERVERS_FILE, "w") as f:
                f.write("\n".join(web_servers))
            print(f"[*] Web servers saved to {WEB_SERVERS_FILE}")
            print(f"[*] Total web servers found: {len(web_servers)}")
    except Exception as e:
        print(f"[!] Error checking web servers: {e}")

def main():
    print_banner()
    parser = argparse.ArgumentParser(description="Scan IPs behind the WAF")
    parser.add_argument("domain", nargs="?", help="Target domain to scan")
    args = parser.parse_args()

    if not args.domain:
        parser.print_help()
        sys.exit(1)

    domain = args.domain
    print(f"[*] Target domain: {domain}")

    check_waf(domain)
    shodan_ips = get_shodan_ips(domain)
    vt_ips = get_virustotal_ips(domain)
    alienvault_ips = get_alienvault_ips(domain)
    urlscan_ips = get_urlscan_ips(domain)
    all_ips = shodan_ips | vt_ips | alienvault_ips | urlscan_ips
    print(f"[*] Total unique IPv4 addresses found: {len(all_ips)}")
    with open(OUTPUT_FILE, "w") as f:
        f.write("\n".join(sorted(all_ips)))
    print(f"[*] All IPs saved to {OUTPUT_FILE}")
    check_web_servers(sorted(all_ips))

if __name__ == "__main__":
    main()
