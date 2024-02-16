<p align="center">
  <img src="https://github.com/jivy26/infiltra/blob/master/logo.png" alt="Infiltra">
</p>

# Goal

To automate and enhance the processes of external penetration testing by integrating advanced Open Source Intelligence (OSINT) and other security tools, streamlining the discovery and analysis phases of security assessments.

# Features

- **Project Management**: Create, load, and manage penetration testing projects with a structured approach.

- **Tool Status Monitoring**: Visual indicators for tool execution status within the current project's context.

- **Whois Analysis**: Comprehensive Whois lookups with parsed organization names for IP range targeting.

- **ICMP Echo Checking**: Identification of live hosts using ICMP echo requests.

- **Open Source Intelligence (OSINT) Gathering**:
  - **AORT & DNSRecon**: In-depth subdomain discovery and DNS analysis.
  - **BBOT**: Black-box penetration testing for detailed security analysis. [Learn about BBOT](https://github.com/blacklanternsecurity/bbot).
  - **Subdomain Enumeration**: Automated enumeration with visual snapshots of live websites.

- **Network Mapping**: Detailed NMAP scans (TCP/UDP) with parsed results to outline network structures.

- **SSL Vulnerability Assessment**: SSLScan execution across IP ranges with parsed output highlighting significant vulnerabilities.

- **Web Server Scanning**: Nikto scans on single or multiple IPs to detect potential web server vulnerabilities.

- **Nuclei Vulnerability Scanning**: Integration of Nuclei scans to identify known vulnerabilities in network infrastructures.

- **Website Enumeration**: A suite of tools including Feroxbuster, Wappalyzer, OWASP ZAP, and WPScan to discover, analyze, and report on web application vulnerabilities.

# New in This Release

- **Feroxbuster Integration**: Automated installation and execution of Feroxbuster for directory brute-forcing, with results stored in project-specific directories.

- **DNSRecon Output Filtering**: Enhanced DNSRecon output to highlight misconfigurations and rerun functionality for thorough examination.

- **WPScan Improvements**: Single domain processing for WPScan to avoid errors and better handle multiple domains.

- **App Data Directory**: Introduction of an application data directory for storing user-specific configurations and API keys.

- **Error Handling and Notifications**: Improved error messages and notifications for background processes and completed scans.

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
