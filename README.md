# Dependencies


**pup and httprobe required for Eyewitness** `apt install pup && httprobe -y`
<br /><br />
# Folder Structure
As long as the EPT folder structure is maintained, you can place the EPT folder anywhere you prefer. Changing the structure will break functionality.
<br /><br />
ept/<br />
├── ept.py<br />
├── eyewitness/<br />
│   └── eyewitness.py<br />
├── nmap-grep.sh<br />
├── nmap_scan.py<br />
├── sslscanparse.py<br />
├── version.txt<br />
└── whois_script.sh<br />
<br /><br />
# Configuration
<br />
The tool works out of the box; however, I recommend creating an alias to handle calls to ept.py for ease of use. The example uses zshrc_aliases; however, the same applies for bash_aliases. Close and reopen the terminal after saving the alias file and type ept to verify the alias is working correctly.
<br /><br />

**Change the path of the EPT folder to where yours is located and use the alias below**
<br />
`alias ept='python3 /home/kali/tools/ept/ept.py'`

![Alt text](https://i.postimg.cc/jS2vqKPb/Virtual-Box-VM-Oi-GQmts0-QG.gif)
