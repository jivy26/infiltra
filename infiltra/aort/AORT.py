#!/usr/bin/env python3

# AORT - All in One Recon Tool
# Author: Jivy2 (Retired D3Ext)
# Github: https://github.com/jivy26/AORT


import sys


# Output Colours
class c:
    PURPLE = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    UNDERLINE = '\033[4m'


# Libraries
try:
    import requests
    import re
    import socket
    import json
    import argparse
    import platform
    import dns.zone
    import warnings
    import dns.resolver
    import pydig
    from time import sleep
    import os
    import urllib3
    from urllib.parse import urlparse
except Exception as e:
    print(e)
    print(
        c.YELLOW + "\n[" + c.RED + "-" + c.YELLOW + "] ERROR requirements missing try to install the requirements: pip3 install -r requirements.txt" + c.END)
    sys.exit(0)


# Banner Function
def banner():
    # Read the AORT version from the version.txt file
    version_file_path = 'version.txt'  # Update the path if needed
    try:
        with open(version_file_path, 'r') as file:
            aort_version = file.read().strip()  # Read and strip any extra whitespace
    except FileNotFoundError:
        aort_version = 'unknown'  # If the file doesn't exist, set version to 'unknown'

    print(c.YELLOW + '                _____                   ')
    print('             .-"     "-.                ')
    print('            / o       o \               ')
    print('           /   \     /   \              ')
    print('          /     )-"-(     \             ')
    print('         /     ( 6 6 )     \            ')
    print('        /       \ " /       \           ')
    print('       /         )=(         \    - Maintained By jivy26')
    print('      /   o   .--"-"--.   o   \   - Created By D3Ext')
    print('     /    I  /  -   -  \  I    \        ')
    print(' .--(    (_}y/\       /\y{_)    )--.    ')
    print('(    ".___l\/__\_____/__\/l___,"    )   ')
    print(' \                                 /    ')
    print('  "-._      o O o O o O o      _,-"     ')
    print('      `--Y--.___________.--Y--\'        ')
    print('         |==.___________.==|            ')
    print('         `==.___________.==\'           ' + c.END)
    print(c.BLUE + "\nCurrent AORT version: " + c.GREEN + aort_version + c.END)
    print(c.BLUE + "Python version: " + c.GREEN + platform.python_version() + c.END)
    print(c.BLUE + "Current OS: " + c.GREEN + platform.system() + " " + platform.release() + c.END)

    internet_check = socket.gethostbyname(socket.gethostname())
    if internet_check == "127.0.0.1":
        if platform.system() == "Windows":
            print(c.BLUE + "Internet connection: " + c.RED + "-" + c.END)
        else:
            print(c.BLUE + "Internet connection: " + c.RED + "✕" + c.END)
    else:
        if platform.system() == "Windows":
            print(c.BLUE + "Internet connection: " + c.GREEN + "+" + c.END)
        else:
            print(c.BLUE + "Internet connection: " + c.GREEN + "✔" + c.END)

    print(c.BLUE + "Target: " + c.GREEN + domain + c.END)


# URL Validation Vuln Found From Github
def is_allowed_url(url, allowed_hosts):
    """
    Check if the URL's hostname is in the list of allowed hosts.

    :param url: The full URL to check.
    :param allowed_hosts: A list of allowed hostnames.
    :return: True if the URL is allowed, False otherwise.
    """
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    return hostname in allowed_hosts


# Argument parser Function
def parseArgs():
    p = argparse.ArgumentParser(description="AORT - All in One Recon Tool")
    p.add_argument("-d", "--domain", help="domain to search its subdomains", required=True)
    p.add_argument("-o", "--output", help="file to store the scan output", required=False)
    p.add_argument('-t', '--token', help="api token of hunter.io to discover mail accounts and employees",
                   required=False)
    p.add_argument("-p", "--portscan", help="perform a fast and stealthy scan of the most common ports",
                   action='store_true', required=False)
    p.add_argument("-a", "--axfr", help="try a domain zone transfer attack", action='store_true', required=False)
    p.add_argument("-m", "--mail", help="try to enumerate mail servers", action='store_true', required=False)
    p.add_argument('-e', '--extra', help="look for extra dns information", action='store_true', required=False)
    p.add_argument("-n", "--nameservers", help="try to enumerate the name servers", action='store_true', required=False)
    p.add_argument("-i", "--ip", help="it reports the ip or ips of the domain", action='store_true', required=False)
    p.add_argument('-6', '--ipv6', help="enumerate the ipv6 of the domain", action='store_true', required=False)
    p.add_argument("-w", "--waf", help="discover the WAF of the domain main page", action='store_true', required=False)
    p.add_argument("-b", "--backups", help="discover common backups files in the web page", action='store_true',
                   required=False)
    p.add_argument("-s", "--subtakeover", help="check if any of the subdomains are vulnerable to Subdomain Takeover",
                   action='store_true', required=False)
    p.add_argument("-r", "--repos",
                   help="try to discover valid repositories and s3 servers of the domain (still improving it)",
                   action='store_true', required=False)
    p.add_argument("-c", "--check", help="check active subdomains and store them into a file", action='store_true',
                   required=False)
    p.add_argument("--secrets", help="crawl the web page to find secrets and api keys (e.g. Google Maps API Key)",
                   action='store_true', required=False)
    p.add_argument("--enum", help="stealthily enumerate and identify common technologies", action='store_true',
                   required=False)
    p.add_argument("--whois", help="perform a whois query to the domain", action='store_true', required=False)
    p.add_argument("--wayback",
                   help="find useful information about the domain and his different endpoints using The Wayback Machine and other services",
                   action="store_true", required=False)
    # p.add_argument("--fuzz", help="use a fuzzing wordlist with common files and directories", actionn='store_true', require=False)
    p.add_argument("--all", help="perform all the enumeration at once (best choice)", action='store_true',
                   required=False)
    p.add_argument("--quiet", help="don't print the banner", action='store_true', required=False)
    p.add_argument("--version", help="display the script version", action='store_true', required=False)
    return p.parse_args()


# Nameservers Function
def ns_enum(domain):
    print(
        c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Trying to discover valid name servers...\n" + c.END)
    sleep(0.2)
    """
    Query to get NS of the domain
    """
    data = ""
    try:
        data = dns.resolver.resolve(f"{domain}", 'NS')
    except:
        pass
    if data:
        for ns in data:
            print(c.YELLOW + str(ns) + c.END)
    else:
        print(c.YELLOW + "Unable to enumerate" + c.END)


# IPs discover Function
def ip_enum(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Discovering IPs of the domain...\n" + c.END)
    sleep(0.2)
    """
    Query to get ips
    """
    data = ""
    try:
        data = dns.resolver.resolve(f"{domain}", 'A')
    except:
        pass
    if data:
        for ip in data:
            print(c.YELLOW + ip.to_text() + c.END)
    else:
        print(c.YELLOW + "Unable to enumerate" + c.END)


# Extra DNS info Function
def txt_enum(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Enumerating extra DNS information...\n" + c.END)
    sleep(0.2)
    """
    Query to get extra info about the dns
    """
    data = ""
    try:
        data = dns.resolver.resolve(domain, 'TXT')
    except:
        pass
    if data:
        for info in data:
            print(c.YELLOW + info.to_text() + c.END)
    else:
        print(c.YELLOW + "Unable to enumerate" + c.END)


# Function to discover the IPv6 of the target
def ipv6_enum(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Getting ipv6 of the domain...\n" + c.END)
    sleep(0.2)
    """
    Query to get ipv6
    """
    data = ""
    try:
        data = pydig.query(domain, 'AAAA')
    except:
        pass
    if data:
        for info in data:
            print(c.YELLOW + info + c.END)
    else:
        print(c.YELLOW + "Unable to enumerate" + c.END)


# Mail servers Function
def mail_enum(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Finding valid mail servers...\n" + c.END)
    sleep(0.2)
    """
    Query to get mail servers
    """
    data = ""
    try:
        data = dns.resolver.resolve(f"{domain}", 'MX')
    except:
        pass
    if data:
        for server in data:
            print(c.YELLOW + str(server).split(" ")[1] + c.END)
    else:
        print(c.YELLOW + "Unable to enumerate" + c.END)


# Domain Zone Transfer Attack Function
def axfr(domain):
    print(
        c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Starting Domain Zone Transfer attack...\n" + c.END)
    sleep(0.2)
    """
    Iterate through the name servers and try an AXFR attack on everyone
    """
    ns_answer = dns.resolver.resolve(domain, 'NS')
    for server in ns_answer:
        ip_answer = dns.resolver.resolve(server.target, 'A')
        for ip in ip_answer:
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(str(ip), domain, timeout=30))
                for host in zone:
                    print(c.YELLOW + "Found Host: {}".format(host) + c.END)
            except Exception as e:
                print(c.YELLOW + "NS {} refused zone transfer!".format(server) + c.END)
                continue


# Modified function from https://github.com/Nefcore/CRLFsuite WAF detector script <3
def wafDetector(domain):
    """
    Get WAFs list in a file
    """
    # Get the absolute path to the directory where the script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))

    # Use os.path.join to construct the path to 'utils/wafsign.json'
    wafsign_path = os.path.join(script_dir, 'utils', 'wafsign.json')

    # Now you can safely load the file using the absolute path
    with open(wafsign_path, 'r') as file:
        wafsigns = json.load(file)

    print(
        c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Discovering active WAF on the main web page...\n" + c.END)
    sleep(1)
    """
    Payload to trigger the possible WAF
    """
    payload = "../../../../etc/passwd"

    try:
        """
        Check the domain and modify if neccessary 
        """
        if domain.endswith("/") and domain.startswith("https://"):
            response = requests.get(domain + payload, verify=False)
        elif domain.endswith("/") and not domain.startswith("https://"):
            response = requests.get('https://' + domain + payload, verify=False)
        elif not domain.endswith("/") and domain.startswith("https://"):
            response = requests.get(domain + '/' + payload, verify=False)
        elif not domain.endswith("/") and not domain.startswith("https://"):
            response = requests.get('https://' + domain + '/' + payload, verify=False)
    except:
        print(c.YELLOW + "An error has ocurred" + c.END)
        try:
            os.remove('wafsign.json')
        except:
            pass
        return None

    code = str(response.status_code)
    page = response.text
    headers = str(response.headers)
    cookie = str(response.cookies.get_dict())
    """
    Check if WAF has blocked the request
    """
    if int(code) >= 400:
        bmatch = [0, None]
        for wafname, wafsign in wafsigns.items():
            total_score = 0
            pSign = wafsign["page"]
            cSign = wafsign["code"]
            hSign = wafsign["headers"]
            ckSign = wafsign["cookie"]
            if pSign:
                if re.search(pSign, page, re.I):
                    total_score += 1
            if cSign:
                if re.search(cSign, code, re.I):
                    total_score += 0.5
            if hSign:
                if re.search(hSign, headers, re.I):
                    total_score += 1
            if ckSign:
                if re.search(ckSign, cookie, re.I):
                    total_score += 1
            if total_score > bmatch[0]:
                del bmatch[:]
                bmatch.extend([total_score, wafname])

        if bmatch[0] != 0:
            print(c.YELLOW + bmatch[1] + c.END)
        else:
            print(c.YELLOW + "WAF not detected or doesn't exists" + c.END)
    else:
        print(c.YELLOW + "An error has ocurred or unable to enumerate" + c.END)

    try:
        os.remove('wafsign.json')
    except:
        pass


# Use the token
def crawlMails(domain, api_token):
    print(c.BLUE + "\n[" + c.GREEN + "+" + c.BLUE + "] Discovering valid mail accounts and employees..." + c.END)
    """
    Use the api of hunter.io with your token to get valid mails
    """
    sleep(1)
    api_url = f"""https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_token}"""
    r = requests.get(api_url)
    response_data = json.loads(r.text)
    domain_name = domain.split(".")[0]
    print()
    file = open(f"{domain_name}-mails-data.txt", "w")
    file.write(r.text)
    file.close()

    counter = 0
    for value in response_data["data"]["emails"]:
        if value["first_name"] and value["last_name"]:
            counter = 1
            print(c.YELLOW + value["first_name"] + " " + value["last_name"] + " - " + value["value"] + c.END)
        else:
            counter = 1
            print(c.YELLOW + value["value"] + c.END)
    if counter == 0:
        print(c.YELLOW + "\nNo mails or employees found" + c.END)
    else:
        print(c.YELLOW + "\nMore mail data stored in " + domain_name + "-mails-data.txt" + c.END)


# Function to check subdomain takeover
def subTakeover(all_subdomains):
    """
    Iterate through all the subdomains to check if anyone is vulnerable to subdomain takeover
    """
    vuln_counter = 0
    print(c.BLUE + "\n[" + c.GREEN + "+" + c.BLUE + "] Checking if any subdomain is vulnerable to takeover\n" + c.END)
    sleep(1)

    for subdom in all_subdomains:
        try:
            sleep(0.05)
            resquery = dns.resolver.resolve(subdom, 'CNAME')
            for resdata in resquery:
                resdata = (resdata.to_text())
                if subdom[-8:] in resdata:
                    r = requests.get("https://" + subdom, allow_redirects=False)
                    if r.status_code == 200:
                        vuln_counter += 1
                        print(c.YELLOW + subdom + " appears to be vulnerable" + c.END)
                else:
                    pass
        except KeyboardInterrupt:
            sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)
        except:
            pass

    if vuln_counter <= 0:
        print(c.YELLOW + "No subdomains are vulnerable" + c.END)


# Function to enumerate github and cloud
def cloudgitEnum(domain):
    print(
        c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Looking for git repositories and public development info\n" + c.END)
    sleep(0.2)
    try:
        r = requests.get("https://" + domain + "/.git/", verify=False)
        print(c.YELLOW + "Git repository URL: https://" + domain + "/.git/ - " + str(
            r.status_code) + " status code" + c.END)
    except:
        pass
    try:
        r = requests.get("https://bitbucket.org/" + domain.split(".")[0])
        print(c.YELLOW + "Bitbucket account URL: https://bitbucket.org/" + domain.split(".")[0] + " - " + str(
            r.status_code) + " status code" + c.END)
    except:
        pass
    try:
        r = requests.get("https://github.com/" + domain.split(".")[0])
        print(c.YELLOW + "Github account URL: https://github.com/" + domain.split(".")[0] + " - " + str(
            r.status_code) + " status code" + c.END)
        # if r.status_code == 200:
        # git_option = input("Do you want to analyze further the github account and its repos? [y/n]: ")
        # if git_option == "y" or git_option == "yes":
        # domain_name = domain.split(".")[0]
        # r = requests.get("https://api.github.com/users/{domain_name}/repos")
        # __import__('pdb').set_trace()
    except:
        pass
    try:
        r = requests.get("https://gitlab.com/" + domain.split(".")[0])
        print(c.YELLOW + "Gitlab account URL: https://gitlab.com/" + domain.split(".")[0] + " - " + str(
            r.status_code) + " status code" + c.END)
    except:
        pass


# Wayback Machine function
def wayback(domain):
    print(
        c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Using The Wayback Machine to discover endpoints" + c.END)
    wayback_url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
    """
    Get information from Wayback Machine
    """
    try:
        r = requests.get(wayback_url, timeout=20)
        results = r.json()
        results = results[1:]
    except KeyboardInterrupt:
        sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)
    except:
        pass

    domain_name = domain.split(".")[0]
    try:
        os.remove(f"{domain_name}-wayback.txt")
    except:
        pass
    for result in results:
        """
        Save data to a file
        """
        file = open(f"{domain_name}-wayback.txt", "a")
        file.write(result[0] + "\n")

    """
    Get URLs and endpoints from URLScan
    """
    try:
        r = requests.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}", timeout=20)
        myresp = json.loads(r.text)
        results = myresp["results"]

        for res in results:
            url = res["task"]["url"]
            file = open(f"{domain_name}-wayback.txt", "a")
            file.write(url + "\n")
    except:
        pass

    print(c.YELLOW + f"\nAll URLs stored in {domain_name}-wayback.txt" + c.END)
    sleep(0.3)
    # Now filter wayback output to organize endpoints
    print(c.YELLOW + f"\nGetting .json endpoints from URLs..." + c.END)
    sleep(0.5)
    try:  # Remove existing file (avoid error when appending data to file)
        os.remove(f"{domain_name}-json.txt")
    except:
        pass
    urls = open(f"{domain_name}-wayback.txt", "r").readlines()
    json_endpoints = []
    for url in urls:
        if ".json" in url and url not in json_endpoints:
            json_endpoints.append(url)
    # Store .json endpoints
    f = open(f"{domain_name}-json-endpoints.txt", "a")
    for json_url in json_endpoints:
        f.write(json_url)
    f.close()
    json_len = len(json_endpoints)
    print(c.YELLOW + f"JSON endpoints stored in {domain_name}-json.txt ({json_len} endpoints)" + c.END)
    sleep(0.4)
    print(c.YELLOW + f"Filtering out URLs to find potential XSS and Open Redirect vulnerable endpoints..." + c.END)
    sleep(0.2)
    wayback_content = open(f"{domain_name}-wayback.txt", "r").readlines()
    redirects_file_exists = 1
    # Check if redirects.json parameters file exists
    try:
        # Directly load the local redirects.json file
        with open("utils/redirects.json", "r") as file:
            redirects = json.load(file)
    except IOError:
        print("Error opening or reading the file 'utils/redirects.json'.")
        # Handle the I/O error (e.g., exit the program or log the error)
    except json.JSONDecodeError:
        print("Error decoding JSON from the file 'utils/redirects.json'.")
        # Handle the JSON parsing error (e.g., exit the program or log the error)

    redirect_urls = []
    redirects_raw = open("redirects.json")
    redirects_json = json.load(redirects_raw)
    for line in wayback_content:
        line = line.strip()
        for json_line in redirects_json["patterns"]:
            if re.findall(rf".*{json_line}.*?", line):
                endpoint_url = re.findall(rf".*{json_line}.*?", line)[0] + "FUZZ"
                if endpoint_url not in redirect_urls:
                    redirect_urls.append(endpoint_url)

    try:  # Remove file if exists
        os.remove(f"{domain_name}-redirects.txt")
    except:
        pass
    # Write open redirects filter content
    f = open(f"{domain_name}-redirects.txt", "a")
    for filtered_url in redirect_urls:
        f.write(filtered_url + "\n")
    f.close()
    end_info = len(redirect_urls)
    print(c.YELLOW + f"Open Redirects endpoints stored in {domain_name}-redirects.txt ({end_info} endpoints)" + c.END)

    # Directly load the local xss.json file
    with open("utils/xss.json", "r") as file:
        xss_patterns = json.load(file)

    # Filter potential XSS
    xss_urls = []
    xss_raw = open("xss.json")
    xss_json = json.load(xss_raw)
    for line in wayback_content:
        line = line.strip()
        for json_line in xss_json["patterns"]:
            if re.findall(rf".*{json_line}.*?", line):
                endpoint_url = re.findall(rf".*{json_line}.*?", line)[0] + "FUZZ"
                if endpoint_url not in xss_urls:
                    xss_urls.append(endpoint_url)

    # Write xss filter content
    f = open(f"{domain_name}-xss.txt", "a")
    for filtered_url in xss_urls:
        f.write(filtered_url + "\n")
    f.close()

    end_info = len(xss_urls)
    print(c.YELLOW + f"XSS endpoints stored in {domain_name}-xss.txt ({end_info} endpoints)" + c.END)
    sleep(0.1)

    if redirects_file_exists == 0:
        os.remove("redirects.json")
    if xss_file_exists == 0:
        os.remove("xss.json")


# Query the domain
def whoisLookup(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Performing Whois lookup..." + c.END)
    import whois
    sleep(1.2)

    try:
        w = whois.whois(domain)  # Two different ways to avoid a strange error
    except:
        w = whois.query(domain)
    try:
        print(c.YELLOW + f"\n{w}" + c.END)
    except:
        print(c.YELLOW + "\nAn error has ocurred or unable to whois " + domain + c.END)


# Function to thread when probing active subdomains
def checkStatus(subdomain, file):
    try:
        r = requests.get("https://" + subdomain, timeout=2)
        # Just check if the web is up and https
        if r.status_code:
            file.write("https://" + subdomain + "\n")
    except:
        try:
            r = requests.get("http://" + subdomain, timeout=2)
            # Check if is up and http
            if r.status_code:
                file.write("http://" + subdomain + "\n")
        except:
            pass


# Check status function
def checkActiveSubs(domain, doms):
    global file
    import threading

    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Probing active subdomains..." + c.END)

    if len(doms) >= 100:
        subs_total = len(doms)
        option = input(
            c.YELLOW + f"\nThere are a lot of subdomains to check, ({subs_total}) do you want to check all of them [y/n]: " + c.END)

        if option == "n" or option == "no":
            sleep(0.2)
            return
    """ Define filename """
    domain_name = domain.split(".")[0]
    file = open(f"{domain_name}-active-subs.txt", "w")
    """
    Iterate through all subdomains in threads
    """
    threads_list = []
    for subdomain in doms:
        t = threading.Thread(target=checkStatus, args=(subdomain, file))
        t.start()
        threads_list.append(t)
    for proc_thread in threads_list:  # Wait until all thread finish
        proc_thread.join()

    print(c.YELLOW + f"\nActive subdomains stored in {domain_name}-active-subs.txt" + c.END)


# Check if common ports are open
def portScan(domain):
    print(
        c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Scanning most common ports on " + domain + "\n" + c.END)
    """ Define ports array """
    ports = [21, 22, 23, 25, 26, 43, 53, 69, 80, 81, 88, 110, 135, 389, 443, 445, 636, 873, 1433, 2049, 3000, 3001,
             3306, 4000, 4040, 5000, 5001, 5985, 5986, 8000, 8001, 8080, 8081, 27017]
    """
    Iterate through the ports to check if are open
    """
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.40)
        result = sock.connect_ex((domain, port))
        if result == 0:
            print(c.YELLOW + "Port " + str(port) + " - OPEN" + c.END)
        sock.close()


# Fuzz a little looking for backups
def findBackups(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Looking for common backup files...\n" + c.END)
    back_counter = 0
    hostname = domain.split(".")[0]
    protocols = ["http", "https"]
    filenames = [hostname, domain, "backup", "admin"]
    extensions = ["sql.tar", "tar", "tar.gz", "gz", "tar.bzip2", "sql.bz2", "sql.7z", "zip", "sql.gz", "7z"]
    # Some common backup filenames with multiple extensions
    for protocol in protocols:
        for filename in filenames:
            for ext in extensions:
                url = protocol + "://" + domain + "/" + filename + "." + ext
                try:
                    r = requests.get(url, verify=False)
                    code = r.status_code
                except:
                    continue
                if code != 404:
                    back_counter += 1
                    print(c.YELLOW + url + " - " + str(code) + c.END)

    if back_counter == 0:
        print(c.YELLOW + "No backup files found" + c.END)


# Look for Google Maps API key and test if it's vulnerable
def findSecrets(domain):
    print(
        c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Trying to found possible secrets and api keys..." + c.END)
    for protocol in ["https", "http"]:
        findSecretsFromUrl(protocol + "://" + domain)


def findSecretsFromUrl(url):
    # Initial request
    try:
        r = requests.get(url, verify=False)
    except:
        return
    js_list = []
    key_counter = 0
    url_list = re.findall(r'src="(.*?)"', r.text) + re.findall(r'href="(.*?)"', r.text)
    # Get JS endpoints
    for endpoint in url_list:
        if ".js" in endpoint and "https://" not in endpoint:
            js_list.append(endpoint)

    if len(js_list) >= 1:
        print(c.YELLOW + "\nDiscovered JS endpoints:" + c.END)
    for js in js_list:
        print(c.YELLOW + url + js + c.END)

    for js_endpoint in js_list:
        try:
            r = requests.get(url + js_endpoint, verify=False)
        except:
            pass

        # Define the list of allowed hosts
        allowed_hosts = ['maps.googleapis.com']

        # Find all URLs in the text
        urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', r.text)

        # Check each URL to see if its hostname is in the list of allowed hosts
        for url in urls:
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            if hostname in allowed_hosts:
                # Extract the API key from the URL if the host is allowed
                maps_api_key_match = re.search(r'https://maps.googleapis.com/maps/api/js\?key=(.*?)&', url)
                if maps_api_key_match:
                    maps_api_key = maps_api_key_match.group(1)
                    print(c.YELLOW + "\nMaps API key found: " + maps_api_key + c.END)
                    key_counter = 1

        try:
            google_api = re.findall(r'AIza[0-9A-Za-z-_]{35}', r.text)[0]
            if google_api:
                print(c.YELLOW + "\nGoogle api found: " + google_api + c.END)
                key_counter = 1
        except:
            pass
        try:
            google_oauth = re.findall(r'ya29\.[0-9A-Za-z\-_]+', r.text)[0]
            if google_oauth:
                print(c.YELLOW + "\nGoogle Oauth found: " + google_oauth + c.END)
                key_counter = 1
        except:
            pass
        try:
            amazon_aws_url = re.findall(r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com', r.text)[0]
            if amazon_aws_url:
                print(c.YELLOW + "\nAmazon AWS url found on " + js_endpoint + c.END)
                key_counter = 1
        except:
            pass
        try:
            stripe_key = re.findall(r'"pk_live_.*"', r.text)[0].replace('"', '')
            if stripe_key:
                print(c.YELLOW + "\nStripe key found on " + js_endpoint + c.END)
                key_counter = 1
        except:
            pass

    if key_counter != 1:
        print(c.YELLOW + "\nNo secrets found" + c.END)


# Perform basic enumeration
def basicEnum(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Performing some basic enumeration...\n" + c.END)
    """
    Use python-Wappalyzer
    """
    try:
        print()
        from Wappalyzer import Wappalyzer, WebPage
        wappalyzer = Wappalyzer.latest()
        webpage = WebPage.new_from_url('https://' + domain)
        info = wappalyzer.analyze_with_versions(webpage)

        if info != "{}":
            print(c.YELLOW + json.dumps(info, sort_keys=True, indent=4) + c.END)
        else:
            print(c.YELLOW + "\nNo common technologies found" + c.END)

        endpoints = ["robots.txt", "xmlrpc.php", "wp-cron.php", "actuator/heapdump", "datahub/heapdump",
                     "datahub/actuator/heapdump", "heapdump", "admin/", ".env", ".config", "version.txt", "README.md",
                     "license.txt", "config.php.bak", "api/", "feed.xml", "CHANGELOG.md", "config.json", "cgi-bin/",
                     "env.json", ".htaccess", "js/", "kibana/", "log.txt"]
        for end in endpoints:
            r = requests.get(f"https://{domain}/{end}", timeout=4)
            print(c.YELLOW + f"https://{domain}/{end} - " + str(r.status_code) + c.END)
    except:
        print(c.YELLOW + "An error has ocurred or unable to enumerate" + c.END)


# Main Domain Discoverer Function
def SDom(domain, filename):
    print(
        c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Discovering subdomains using passive techniques...\n" + c.END)
    sleep(0.1)
    global doms
    doms = []
    """
    Get valid subdomains from crt.sh
    """
    try:
        r = requests.get("https://crt.sh/?q=" + domain + "&output=json", timeout=20)
        formatted_json = json.dumps(json.loads(r.text), indent=4)
        crt_domains = sorted(set(re.findall(r'"common_name": "(.*?)"', formatted_json)))
        # Only append new valid subdomains
        for dom in crt_domains:
            if dom.endswith(domain) and dom not in doms:
                doms.append(dom)

    except KeyboardInterrupt:
        sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)
    except:
        pass
    """
    Get subdomains from AlienVault
    """
    try:
        r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", timeout=20)
        alienvault_domains = sorted(set(re.findall(r'"hostname": "(.*?)"', r.text)))
        # Only append new valid subdomains
        for dom in alienvault_domains:
            if dom.endswith(domain) and dom not in doms:
                doms.append(dom)
    except KeyboardInterrupt:
        sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)
    except:
        pass
    """
    Get subdomains from Hackertarget
    """
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=20)
        hackertarget_domains = re.findall(r'(.*?),', r.text)
        # Only append new valid subdomains
        for dom in hackertarget_domains:
            if dom.endswith(domain) and dom not in doms:
                doms.append(dom)
    except KeyboardInterrupt:
        sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)
    except:
        pass
    """
    Get subdomains from RapidDNS
    """
    try:
        r = requests.get(f"https://rapiddns.io/subdomain/{domain}", timeout=20)
        rapiddns_domains = re.findall(r'target="_blank".*?">(.*?)</a>', r.text)
        # Only append new valid subdomains
        for dom in rapiddns_domains:
            if dom.endswith(domain) and dom not in doms:
                doms.append(dom)
    except KeyboardInterrupt:
        sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)
    except:
        pass
    """
    Get subdomains from Riddler
    """
    try:
        r = requests.get(f"https://riddler.io/search/exportcsv?q=pld:{domain}", timeout=20)
        riddler_domains = re.findall(r'\[.*?\]",.*?,(.*?),\[', r.text)
        # Only append new valid subdomains
        for dom in riddler_domains:
            if dom.endswith(domain) and dom not in doms:
                doms.append(dom)
    except KeyboardInterrupt:
        sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)
    except:
        pass
    """
    Get subdomains from ThreatMiner
    """
    try:
        r = requests.get(f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5", timeout=20)
        raw_domains = json.loads(r.content)
        threatminer_domains = raw_domains['results']
        # Only append new valid subdomains
        for dom in threatminer_domains:
            if dom.endswith(domain) and dom not in doms:
                doms.append(dom)
    except KeyboardInterrupt:
        sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)
    except:
        pass
    """
    Get subdomains from URLScan
    """
    try:
        r = requests.get(f"https://urlscan.io/api/v1/search/?q={domain}", timeout=20)
        urlscan_domains = sorted(set(re.findall(r'https://(.*?).' + domain, r.text)))
        # Only append new valid subdomains
        for dom in urlscan_domains:
            dom = dom + "." + domain
            if dom.endswith(domain) and dom not in doms:
                doms.append(dom)
    except KeyboardInterrupt:
        sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)
    except:
        pass

    if filename != None:
        f = open(filename, "a")

    if doms:
        """
        Iterate through the subdomains and check the lenght to print them in a table format
        """
        print(c.YELLOW + "+" + "-" * 47 + "+")
        for value in doms:

            if len(value) >= 10 and len(value) <= 14:
                print("| " + value + "    \t\t\t\t|")
                if filename != None:
                    f.write(value + "\n")
            if len(value) >= 15 and len(value) <= 19:
                print("| " + value + "\t\t\t\t|")
                if filename != None:
                    f.write(value + "\n")
            if len(value) >= 20 and len(value) <= 24:
                print("| " + value + "   \t\t\t|")
                if filename != None:
                    f.write(value + "\n")
            if len(value) >= 25 and len(value) <= 29:
                print("| " + value + "\t\t\t|")
                if filename != None:
                    f.write(value + "\n")
            if len(value) >= 30 and len(value) <= 34:
                print("| " + value + " \t\t|")
                if filename != None:
                    f.write(value + "\n")
            if len(value) >= 35 and len(value) <= 39:
                print("| " + value + "   \t|")
                if filename != None:
                    f.write(value + "\n")
            if len(value) >= 40 and len(value) <= 44:
                print("| " + value + " \t|")
                if filename != None:
                    f.write(value + "\n")
        """
        Print summary
        """
        print("+" + "-" * 47 + "+" + c.END)
        print(c.YELLOW + "\nTotal discovered sudomains: " + str(len(doms)) + c.END)
        """
        Close file if "-o" parameter was especified
        """
        if filename != None:
            f.close()
            print(c.BLUE + "\n[" + c.GREEN + "+" + c.BLUE + "] Output stored in " + filename)
    else:
        print(c.YELLOW + "No subdomains discovered through SSL transparency" + c.END)


# Check if the given target is active
def checkDomain(domain):
    try:
        addr = socket.gethostbyname(domain)
    except:
        print(c.YELLOW + "\nTarget doesn't exists or is down" + c.END)
        sys.exit(1)


# Program workflow starts here
if __name__ == '__main__':
    program_version = 1.7
    urllib3.disable_warnings()
    warnings.simplefilter('ignore')

    if "--version" in sys.argv:
        print("\nAll in One Recon Tool v" + str(program_version) + " - By D3Ext")
        print("Contact me: <d3ext@proton.me>\n")
        sys.exit(0)

    parse = parseArgs()

    # Check domain format
    if "." not in parse.domain:
        print(c.YELLOW + "\nInvalid domain format, example: domain.com" + c.END)
        sys.exit(0)

    # If --output is passed (store subdomains in file)
    if parse.output:
        store_info = 1
        filename = parse.output
    else:
        filename = None

    global domain

    domain = parse.domain
    checkDomain(domain)
    """
    If --all is passed do all enumeration processes
    """
    if parse.domain and parse.all:

        if domain.startswith('https://'):
            domain = domain.split('https://')[1]
        if domain.startswith('http://'):
            domain = domain.split('http://')[1]

        try:
            if not parse.quiet:
                banner()
            SDom(domain, filename)
            portScan(domain)
            ns_enum(domain)
            axfr(domain)
            mail_enum(domain)
            ip_enum(domain)
            ipv6_enum(domain)
            txt_enum(domain)
            whoisLookup(domain)
            basicEnum(domain)
            findBackups(domain)
            findSecrets(domain)
            cloudgitEnum(domain)
            wafDetector(domain)
            checkActiveSubs(domain, doms)
            wayback(domain)
            subTakeover(doms)

            if parse.token:
                crawlMails(domain, parse.token)
            else:
                print(
                    c.BLUE + "\n[" + c.GREEN + "-" + c.BLUE + "] No API token provided, skipping email crawling" + c.END)
            try:
                file.close()
            except:
                pass
        except KeyboardInterrupt:
            sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)

        sys.exit(0)

    """
    Enter in this part if the --all isn't passed
    """
    if parse.domain:
        domain = parse.domain

        if domain.startswith('https://'):
            domain = domain.split('https://')[1]
        if domain.startswith('http://'):
            domain = domain.split('http://')[1]

        try:
            if not parse.quiet:
                banner()
            SDom(domain, filename)
            """
            Check the passed arguments via command line
            """
            if parse.portscan:
                portScan(domain)
            if parse.nameservers:
                ns_enum(domain)
            if parse.axfr:
                axfr(domain)
            if parse.mail:
                mail_enum(domain)
            if parse.ip:
                ip_enum(domain)
            if parse.ipv6:
                ipv6_enum(domain)
            if parse.extra:
                txt_enum(domain)
            if parse.whois:
                whoisLookup(domain)
            if parse.enum:
                basicEnum(domain)
            if parse.backups:
                findBackups(domain)
            if parse.secrets:
                findSecrets(domain)
            if parse.repos:
                cloudgitEnum(domain)
            if parse.waf:
                wafDetector(domain)
            if parse.check:
                checkActiveSubs(domain, doms)
            if parse.wayback:
                wayback(domain)
            if parse.subtakeover:
                subTakeover(doms)
            if parse.token:
                crawlMails(domain, parse.token)

        except KeyboardInterrupt:
            sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)