
# B3H1ND - WAF IP Checker

B3H1ND is a Python-based tool designed to help cybersecurity professionals scan IP addresses behind a Web Application Firewall (WAF). It gathers IPs associated with a domain from multiple sources and identifies active web servers, assisting in penetration testing and vulnerability assessments.

---

## Features

- **WAF Detection**: Identifies if a target domain is behind a WAF and the WAF type (e.g., Cloudfront, Akamai, etc.).
- **IP Enumeration**:
  - Fetches associated IPs from multiple data sources:
    - [Shodan](https://www.shodan.io/)
    - [VirusTotal](https://www.virustotal.com/)
    - [AlienVault](https://otx.alienvault.com/)
    - [URLScan.io](https://urlscan.io/)
- **Web Server Detection**:
  - Identifies which IPs are hosting web servers and provides additional details such as HTTP status and server title.

---

## Prerequisites

1. **Python**: Ensure Python 3.6+ is installed on your system.
2. **Dependencies**: Install required Python libraries using `pip`:
   ```bash
   pip install -r requirements.txt
   ```
3. **API Keys**:
   - Obtain API keys for:
     - Shodan
     - VirusTotal
   - Update the keys in the script:
     ```python
     SHODAN_API_KEY = "your_shodan_api_key"
     VT_API_KEY = "your_virustotal_api_key"
     ```

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yezeiyashein/b3h1nd.git
   cd b3h1nd
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## Usage

Run the tool with a target domain:

```bash
python b3h1nd.py <DOMAIN>
```

### Example:

```bash
python b3h1nd.py example.com
```

### Help:

```bash
python b3h1nd.py --help
```

---

## Output

1. **WAF Detection**:
   - Detects whether the target is behind a WAF and identifies the WAF type.
   
2. **IP Addresses**:
   - Collects unique IP addresses related to the target domain and saves them in `ip_list.txt`.
   
3. **Web Servers**:
   - Lists active web servers from the IP list, displaying:
     - IP address
     - HTTP status code
     - Title/Server details
   - Saves the results in `web_servers.txt`.

---

## Requirements

- `wafw00f`: Tool for WAF detection.
- `httpx-toolkit`: Used for identifying active web servers.

Install these tools using the following commands:

```bash
pip install wafw00f
pip install httpx-toolkit
```

---

## Example Output

```plaintext
[*] Target domain: example.com
[*] Checking if example.com is behind a WAF...
[+] The site example.com is behind Cloudfront (Amazon) WAF.
[*] Fetching IPs from Shodan...
[*] Fetching IPs from VirusTotal...
[*] Fetching IPs from AlienVault...
[*] Fetching IPs from URLScan.io...
[*] Total unique IPv4 addresses found: 246
[*] Checking which IPs are running web servers...
+--------------+-------------+-------------------------------------+
| IP Address   | HTTP Status | Title/Server                       |
+--------------+-------------+-------------------------------------+
| 192.0.2.1    | 200         | Example Server                     |
+--------------+-------------+-------------------------------------+
[*] Web servers saved to web_servers.txt
[*] Total web servers found: 1
```

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Contributions

Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/yezeiyashein/b3h1nd/issues) for open issues or submit a pull request.

---

## Author

- **N4RG4**
