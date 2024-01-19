# Clone Repo
Run the following command in Kali terminal `git clone https://github.com/jivy26/ept`
<br /><br />

# Install Script
Give the install script executable permissions `sudo chmod +x install.sh`
<br /><br />
Then run it using `./install.sh` and follow prompts

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
