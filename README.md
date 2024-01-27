# Goal
Automate basic external penetration test processes.

# Features

- **Whois Analysis** - Perform Whois lookups against an IP range and parse the results by organization name.

- **ICMP Echo Checking** - Check for ICMP Echo responses across an IP range and parse alive hosts.

- **Open Source Intelligence (OSINT) Tools**
  - **AORT & DNSRecon**: Employ for detailed subdomain enumeration.
  - **BBOT**: Utilize for comprehensive black-box penetration testing. More info on BBOT here: https://github.com/blacklanternsecurity/bbot

- **Network Mapping** - Run NMAP scans (TCP and UDP) and process the findings.

- **SSL Vulnerability Assessment** - Run SSLScans on a range of IPs and parse findings.

- **Subdomain Enumeration** - Enumerate subdomains and capture screenshots of any websites enumerated.

- **Web Server Scanning** - Conduct Nikto scans over an IP range.



# Installation
:warning: _**Do not use sudo to clone repo or run install.sh script**_ :warning:

- **Clone Repo**
<br />
Run the following command in Kali terminal `git clone https://github.com/jivy26/ept`
<br /><br />
- **Install Script**
<br /> 
Give the install script executable permissions `chmod +x install.sh`
<br /><br />
- **Run installation script**
<br />
`./install.sh` and follow prompts 

# Dependencies

**pup and httprobe required for Eyewitness** `apt install pup && httprobe -y`
<br /><br />

# Folder Structure
As long as the EPT folder structure is maintained, you can place the EPT folder anywhere you prefer. Changing the structure will break functionality.
<br /><br />
ept/<br />
├── ept.py<br />
├── aort<br />
├── eyewitness/<br />
│   └── eyewitness.py<br />
├── nmap-grep.sh<br />
├── nmap_scan.py<br />
├── sslscanparse.py<br />
├── version.txt<br />
└── whois_script.sh<br />
