<p align="center">
  <img src="https://github.com/jivy26/infiltra/blob/master/logo.png" alt="Infiltra">
</p>

# Goal

Automate and streamline the basic processes of external penetration testing while incorporating advanced Open Source Intelligence (OSINT) techniques to enhance the discovery and analysis phase of security assessments.

# Features

- **Project Management**: Organize and manage penetration testing projects with ease.

- **Tool Status Monitoring**: Visually identify which tools have been executed in the current project.

- **Whois Analysis**: Perform comprehensive Whois lookups and extract organization names for targeted IP ranges.

- **ICMP Echo Checking**: Probe and list alive hosts across an IP range using ICMP echo requests.

- **Open Source Intelligence (OSINT) Gathering**:
  - **AORT & DNSRecon**: Leverage these tools for in-depth subdomain discovery.
  - **BBOT**: Implement black-box penetration testing methods for a robust security posture analysis. [More about BBOT](https://github.com/blacklanternsecurity/bbot).
  - **Subdomain Enumeration**: Automatically enumerate subdomains and snapshot live websites for a visual inventory.

- **Network Mapping**: Conduct thorough NMAP scans (TCP/UDP) and parse the results for a detailed network structure overview.

- **SSL Vulnerability Assessment**: Execute SSLScans across IP ranges and succinctly parse only the significant findings.

- **Web Server Scanning**: Utilize Nikto for scanning single or multiple IPs to uncover potential web server vulnerabilities.

- **Nuclei Vulnerability Scanning**: Integrate Nuclei scanning (limited functionality in the current version) to identify known vulnerabilities within network infrastructure.

# Examples

### WHOIS Parsing against multiple IP Addresses
<p align="center">
  <img src="https://i.postimg.cc/RZQYspkT/Virtual-Box-VM-e76-LMZLLd2.gif" alt="WHOIS Parsing">
</p>


### ICMP Echo Parsing against multiple IP Addresses
<p align="center">
  <img src="https://i.postimg.cc/zfGxdzSJ/Virtual-Box-VM-f-P6-T2-JM1t-O.gif" alt="ICMP Echo Parsing">
</p>


### DNS Enumeration
<p align="center">
  <img src="https://i.postimg.cc/rsxjdKc9/Virtual-Box-VM-kt-Sl9c1ls7.gif" alt="DNS Enumeration">
</p>


### SSLScan and Parse against multiple IP Addresses
<p align="center">
  <img src="https://i.postimg.cc/wxLQQR8X/Virtual-Box-VM-S48f9g-L6w-H.gif" alt="SSLScan Parser">
</p>

# Installation

Depending on your environment, you might need to run the one-liner with SUDO to avoid permission issues.

- **Installing Infiltra via PIP**<br />
  - `pip install infiltra`
  <br />or
  <br />
  - `sudo pip install infiltra`
  <br /><br />
- **Upgrading Infiltra via PIP**
<br />
  - `pip install --upgrade infiltra`
  <br /><br />
- Use `infiltra` from anywhere to load the tool

# Troubleshooting

**/.local/bin PATH is not defined when installing**
<p align="center">
  <img src="https://i.postimg.cc/G3qrG8y7/Warning.png" alt="Error">
</p>
- Solution: add `export PATH="$HOME/.local/bin:$PATH"` to .zshrc or .bashrc depending on your environment
