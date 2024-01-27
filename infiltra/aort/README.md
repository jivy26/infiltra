# All in One Recon Tool
**Credit to D3Ext for this tool, he has removed it from GitHub so I have forked to maintain as its my favorite subdomain recon tool**

`An easy-to-use python tool to perform subdomain enumeration, endpoints recon and much more`

The purpouse of this tool is helping bug hunters and pentesters during reconnaissance

## Installation:
It can be used in any system with python3

You can easily install AORT using pip:
```sh
pip3 install aort
```

To use it just type "**aort**" into your terminal

If you want to install it from source:
```sh
git clone https://github.com/jivy26/aort
cd AORT
pip3 install -r requirements.txt
```

## Help Panel:

```
AORT - All in One Recon Tool

options:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        domain to search its subdomains
  -o OUTPUT, --output OUTPUT
                        file to store the scan output
  -t TOKEN, --token TOKEN
                        api token of hunter.io to discover mail accounts and employees
  -p, --portscan        perform a fast and stealthy scan of the most common ports
  -a, --axfr            try a domain zone transfer attack
  -m, --mail            try to enumerate mail servers
  -e, --extra           look for extra dns information
  -n, --nameservers     try to enumerate the name servers
  -i, --ip              it reports the ip or ips of the domain
  -6, --ipv6            enumerate the ipv6 of the domain
  -w, --waf             discover the WAF of the domain main page
  -b, --backups         discover common backups files in the web page
  -s, --subtakeover     check if any of the subdomains are vulnerable to Subdomain Takeover
  -r, --repos           try to discover valid repositories and s3 servers of the domain (still improving it)
  -c, --check           check active subdomains and store them into a file
  --secrets             crawl the web page to find secrets and api keys (e.g. Google Maps API Key)
  --enum                stealthily enumerate and identify common technologies
  --whois               perform a whois query to the domain
  --wayback             find useful information about the domain and his different endpoints using The Wayback Machine and other services
  --all                 perform all the enumeration at once (best choice)
  --quiet               don't print the banner
  --version             display the script version
```

## Usage:

- A list of examples to use the tool in different ways 

> Most basic usage to dump all the subdomains
```sh
python3 AORT.py -d example.com
```

> Enumerate subdomains and store them in a file
```sh
python3 AORT.py -d example.com --output domains.txt
```

> Don't show banner
```sh
python3 AORT.py -d example.com --quiet
```

> Enumerate specifics things using parameters
```sh
python3 AORT.py -d example.com -n -p -w -b --whois --enum # You can use other parameters, see help panel
```

> Perform all the recon functions (recommended)
```sh
python3 AORT.py -d domain.com --all
```

## Features:

:ballot_box_with_check: Enumerate subdomains using passive techniques (like **subfinder**)

:ballot_box_with_check: A lot of extra queries to enumerate the DNS

:ballot_box_with_check: Domain Zone transfer attack

:ballot_box_with_check: WAF type detection

:ballot_box_with_check: Common enumeration (CMSs, reverse proxies, jquery...)

:ballot_box_with_check: Whois target domain

:ballot_box_with_check: Subdomain Takeover checker

:ballot_box_with_check: Scan common open ports

:ballot_box_with_check: Check active subdomains (like **httprobe**)

:ballot_box_with_check: Wayback machine support to enumerate endpoints (like **waybackurls**)

:ballot_box_with_check: Email harvesting

## Todo:

- Compare results with other tools such as **subfinder**, **gau**, **httprobe**...
- Improve code and existings functions

## Demo:

> Simple query to find valid subdomains
<img src="https://raw.githubusercontent.com/D3Ext/AORT/main/demo.png">

## Third part

The tool uses different services to get subdomains in different ways

The WAF detector was modified and adapted from [CRLFSuite](https://github.com/Nefcore/CRLFsuite) concept <3

All DNS queries use **dns-python** at 100%, no **dig** or any extra tool needed

Email harvesting functions is done using **Hunter.io** API with personal token (free signup)



