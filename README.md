<p align="center">
  <img src="https://github.com/jivy26/infiltra/blob/master/logo.png" alt="Infiltra">
</p>

# Goal

Automate and streamline the basic processes of external penetration testing while incorporating advanced Open Source Intelligence (OSINT) techniques to enhance the discovery and analysis phase of security assessments.

# Features

- **Project Management**: Organize and manage penetration testing projects with ease, keeping track of the progress and tools used within each project.

- **Tool Status Monitoring**: Visually identify which tools have been executed in the current project, improving workflow efficiency and management.

- **Whois Analysis**: Perform comprehensive Whois lookups and extract organization names for targeted IP ranges, aiding in the identification of potential vectors.

- **ICMP Echo Checking**: Probe and list alive hosts across an IP range using ICMP echo requests, essential for initial network reconnaissance.

- **Open Source Intelligence (OSINT) Gathering**:
  - **AORT & DNSRecon**: Leverage these tools for in-depth subdomain discovery.
  - **BBOT**: Implement black-box penetration testing methods for a robust security posture analysis. [More about BBOT](https://github.com/blacklanternsecurity/bbot).
  - **Subdomain Enumeration**: Automatically enumerate subdomains and snapshot live websites for a visual inventory.

- **Network Mapping**: Conduct thorough NMAP scans (TCP/UDP) and parse the results for a detailed network structure overview.

- **SSL Vulnerability Assessment**: Execute SSLScans across IP ranges and succinctly parse only the significant findings, streamlining the vulnerability identification process.

- **Web Server Scanning**: Utilize Nikto for scanning single or multiple IPs to uncover potential web server vulnerabilities.

- **Nuclei Vulnerability Scanning**: Integrate Nuclei scanning (limited functionality in the current version) to identify known vulnerabilities within network infrastructure.

# Installation

- **One-liner Install**<br />
Run the following command in Kali terminal:<br />
`git clone https://github.com/jivy26/infiltra.git && cd infiltra && pip install . && cd ~/ && sudo rm -R infiltra && infiltra`
<br /><br />
- Use `infiltra` from anywhere to load the tool

<p align="center">
  <img src="https://i.postimg.cc/LhdtrDTw/Virtual-Box-VM-V0x-Ym-EYobq.gif" alt="Install">
</p>
