<p align="center">
  <img src="https://github.com/jivy26/infiltra/blob/master/logo.png" alt="Infiltra">
</p>

# Goal
Automate basic external penetration test processes and integrate advanced OSINT.

# Features

- **Whois Analysis** - Perform Whois lookups against an IP range and parse the results by organization name.

- **ICMP Echo Checking** - Check for ICMP Echo responses across an IP range and parse alive hosts.

- **Open Source Intelligence (OSINT) Tools**
  - **AORT & DNSRecon**: Employ for detailed subdomain enumeration.
  - **BBOT**: Utilize for comprehensive black-box penetration testing. More info on BBOT here: https://github.com/blacklanternsecurity/bbot
  - **Subdomain Enumeration** - Enumerate subdomains and capture screenshots of any websites enumerated.

- **Network Mapping** - Run NMAP scans (TCP and UDP) and process the findings.

- **SSL Vulnerability Assessment** - Run SSLScans on a range of IPs and parse findings.

- **Web Server Scanning** - Conduct Nikto scans over an IP range.

# Dependencies

**pup and httprobe required for Eyewitness** `apt install pup && httprobe -y`
<br />

# Installation
:warning: _**Do not use sudo to clone repo or run install.sh script**_ :warning:

- **Clone Repo**
Run the following command in Kali terminal `git clone https://github.com/jivy26/ept`
- **Install Script**
Give the install script executable permissions `chmod +x install.sh`<br />
- **Run installation script**
`./install.sh` and follow prompts 
