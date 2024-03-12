<p align="center">
  <img src="https://github.com/jivy26/infiltra/blob/master/logo.png" alt="Infiltra">
</p>

[![Downloads](https://static.pepy.tech/badge/infiltra/month)](https://pepy.tech/project/infiltra) [![Downloads](https://static.pepy.tech/badge/infiltra/week)](https://pepy.tech/project/infiltra)

# Goal

To automate and enhance the processes of external penetration testing by integrating advanced Open Source Intelligence (OSINT) and other security tools, streamlining the discovery and analysis phases of security assessments.

# Features

## Project Management
- **Create, Load, or Delete Projects**: Manage your penetration testing projects efficiently, from initiation to completion.

## Information Gathering
- **Whois Lookups**: Conduct Whois lookups and parse results for organizational details.
- **ICMP Echo**: Utilize ICMP echo requests to discover live hosts within a network.
- **OSINT & Black Box OSINT**: Leverage tools like AORT, DNS Recon, BBOT, and EyeWitness for reconnaissance and analysis.

## Scanning and Enumeration
- **NMAP Scanning**: Run comprehensive NMAP scans for both TCP and UDP to map out network structures.
- **Website Enumeration**: Employ techniques such as directory brute-forcing and technology identification for web analysis.
- **VoIP (SIP) Testing**: Test VoIP devices using various SIPTPS modules.

## Parsing and Analysis
- **SSLScan and Parse**: Execute SSLScans over IP ranges and parse the output for significant findings.
- **SSH-Audit and Parse**: Conduct SSH-Audit for security checks and parse the results.

## Vulnerability Scanning
- **NTP Testing (Not Working)**: Intended for running NTPQ and Metasploit against NTP servers.

## Additional Utilities
- **NMAP Parser**: Now located in the NMAP Menu for enhanced scanning and result parsing.
- **Feroxbuster for Directory Brute Forcing**: Discover hidden directories and files within web servers.
- **Identify Technologies with Wappalyzer (Not Working)**: Detect technologies used by web applications.
- **Perform OWASP ZAP Scan (Not Working)**: Analyze web applications for vulnerabilities.
- **Run WPScan for WordPress Sites (Not Working)**: Inspect WordPress sites for security weaknesses.
- **Nikto Web Scans**: Scan web servers to identify potential security issues.

## VoIP Testing Utilizing SIPPTS
- **SIPPTS Tools**: Identify VoIP services, enumerate VoIP methods and extensions, and attempt to send VoIP invites using various SIPPTS tools.

Note: Some features are currently not working and are in the process of being fixed or improved.


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
