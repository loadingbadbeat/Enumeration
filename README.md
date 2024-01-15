<b>1. OSINT Tools -</b>
This is one of the most popular toolkit through which we can gather information.

<b>2. Sublist3r - </b>
Sublist3r is a popular Python tool used to enumerate subdomains of a domain. It uses search engines like Google, Yahoo, and Bing to discover valid subdomains existing on an application.

<b>3. theHarvester - </b>
theHarvester is one of the most popular tool to identify subdomains, emails, IP Addresses, Social network profiles, etc. It is already in Kali Linux.

<b>4. Knockpy -</b>
Knockpy is a simple script that will help us to discover subdomains information. This is the default in Kali Linux.

<b>5. Dnsdumpster - </b>
This is a website through which you can gather information related to DNS records, subdomains, etc.

<b>6. Aquatone  - </b>
Aquatone includes a set of OSINT tools for performing information gathering on a domain. We can perform subdomains discovery, port scanning, and integrates APIs to get more information about any target domain.

<b>7. Amass - </b>
Amass is an open-source tool developed by the Open Web Application Security Project for information gathering. Security professionals and researchers use Amass for domain and subdomain enumeration, network mapping, DNS enumeration, etc.

<b>8. DNSRecon- </b>
DNSRecon is a DNS enumeration tool that can perform various queries such as brute-force subdomains and reverse lookups. It is a very popular and versatile tool used by penetration testers in the information-gathering stage

<b>9. Fierce - </b>
Fierce is a DNS reconnaissance tool, and you can use it to enumerate subdomains.

<b>10. Assetfinder -</b>
assetfinder is a Golang-based tool used for subdomain enumeration on Linux. It discovers subdomains by searching various public sources such as Common Crawl, DNSdumpster, and VirusTotal.



Thanks to - https://atryharder.gitbook.io/try-harder-journey/recon-enumeration

Recon/Enumeration
nmap,nikto.etc notes/cheatsheet
Nmap 
Port Scan Command Lines:
kali@kali#sudo nmap -sV -v -p- --min-rate=10000 10.10.10.5
kali@kali#sudo nmap -sC -sV 10.10.10.5 -Pn
kali@kali#sudo nmap -sC -sS -sV -vv -A -oN nmapscan 10.10.10.5
kali@kali#sudo nmap -T4 -p- -A 10.10.10.5
Notes:
-p-: Scan ALL ports for specified host
-A :This combines OS detection, service version detection, script scanning and traceroute.
-sV :Version detection scan of open ports (services
-T4: Aggressive (fast and fairly accurate)
-sS: This sends only a TCP SYN packet and waits for a TCP ACK. If it receives an ACK on the specific probed port, it means the port exist on the machine. This is fast and pretty accurate.
-sT: This creates a full TCP connection with the host (full TCP handshake). This is considered more accurate than SYN scan but slower and noisier.
-sP: This is for fast checking which hosts reply to ICMP ping packets (useful if you are on the same subnet as the scanned range and want a fast result about how many live hosts are connected).
-Pn: Don’t ping the hosts, assume they are up.
-oN: Normal text format.
Vulnerabilities Scan Example Command Lines:
kali@kali# sudo ls /usr/share/nmap/scripts/ | grep smb | grep vuln
smb2-vuln-uptime.nse
smb-vuln-conficker.nse
smb-vuln-cve2009-3103.nse
smb-vuln-cve-2017-7494.nse
smb-vuln-ms06-025.nse
smb-vuln-ms07-029.nse
smb-vuln-ms08-067.nse
smb-vuln-ms10-054.nse
smb-vuln-ms10-061.nse
smb-vuln-ms17-010.nse
smb-vuln-regsvc-dos.nse
kali@kali# sudo nmap --script smb-vuln* -p 445 -oA nmap/smb_vulns 10.10.10.5
Details reference link:​
Nikto
Scan Command Line:
kali@kali#sudo nikto -host 10.10.10.5
nikto -h "http://10.10.10.5" | tee nikto.log   
Details reference link:​
ffuf - Fuzz Faster U Fool
Installation:
kali@kali#sudo apt update
kali@kali#sudo apt install ffuf -y
Usage Example:
ffuf -ic -w /usr/share/wordlists/dirb/common.txt -e '' -u "http://10.10.10.5/FUZZ" | tee "recon/fuff.txt"
Details reference link:​
dirsearch - Web path discovery
Current Release: v0.4.2 (2021.9.12)
An advanced command-line tool designed to brute force directories and files in webservers, AKA web path scanner.
Usage example:
dirsearch.py -u http://10.10.10.5 or python3 dirsearch.py -u http://10.10.10.5
Github link:​
WPSCAN
​​
wpscan --url 10.10.10.5 --enumerate vp,u,vt,tt
How to install: sudo apt install wpscan
Gobust
​
Installation:
kali@kali#sudo apt update
kali@kali#sudo apt install gobuster -y
Usage Example:
gobuster dir -u http://10.10.10.5/ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -x php
gobuster dir -u http://10.10.10.5 -w /usr/share/wordlists/dirb/common.txt 
dns Mode Help:
Usage:
  gobuster dns [flags]
​
Flags:
  -d, --domain string      The target domain
  -h, --help               help for dns
  -r, --resolver string    Use custom DNS server (format server.com or server.com:port)
  -c, --show-cname         Show CNAME records (cannot be used with '-i' option)
  -i, --show-ips           Show IP addresses
      --timeout duration   DNS resolver timeout (default 1s)
      --wildcard           Force continued operation when wildcard found
​
Global Flags:
  -z, --no-progress       Don't display progress
  -o, --output string     Output file to write results to (defaults to stdout)
  -q, --quiet             Don't print the banner and other noise
  -t, --threads int       Number of concurrent threads (default 10)
      --delay duration    Time each thread waits between requests (e.g. 1500ms)
  -v, --verbose           Verbose output (errors)
  -w, --wordlist string   Path to the wordlist
​
dns Model Example Command Line:
gobuster dns -d mysite.com -t 50 -w common-names.txt
dir Mode Options
Usage:
  gobuster dir [flags]
​
Flags:
  -f, --add-slash                     Append / to each request
  -c, --cookies string                Cookies to use for the requests
  -e, --expanded                      Expanded mode, print full URLs
  -x, --extensions string             File extension(s) to search for
  -r, --follow-redirect               Follow redirects
  -H, --headers stringArray           Specify HTTP headers, -H 'Header1: val1' -H 'Header2: val2'
  -h, --help                          help for dir
  -l, --include-length                Include the length of the body in the output
  -k, --no-tls-validation             Skip TLS certificate verification
  -n, --no-status                     Don't print status codes
  -P, --password string               Password for Basic Auth
  -p, --proxy string                  Proxy to use for requests [http(s)://host:port]
  -s, --status-codes string           Positive status codes (will be overwritten with status-codes-blacklist if set) (default "200,204,301,302,307,401,403")
  -b, --status-codes-blacklist string Negative status codes (will override status-codes if set)
      --timeout duration              HTTP Timeout (default 10s)
  -u, --url string                    The target URL
  -a, --useragent string              Set the User-Agent string (default "gobuster/3.1.0")
  -U, --username string               Username for Basic Auth
  -d, --discover-backup               Upon finding a file search for backup files
      --wildcard                      Force continued operation when wildcard found
​
Global Flags:
  -z, --no-progress       Don't display progress
  -o, --output string     Output file to write results to (defaults to stdout)
  -q, --quiet             Don't print the banner and other noise
  -t, --threads int       Number of concurrent threads (default 10)
      --delay duration    Time each thread waits between requests (e.g. 1500ms)
  -v, --verbose           Verbose output (errors)
  -w, --wordlist string   Path to the wordlist
​
dir Model Example Command Line:
gobuster dir -u https://mysite.com/path/to/folder -c 'session=123456' -t 50 -w common-files.txt -x .php,.html
vhost Mode Options
Usage:
  gobuster vhost [flags]
​
Flags:
  -c, --cookies string        Cookies to use for the requests
  -r, --follow-redirect       Follow redirects
  -H, --headers stringArray   Specify HTTP headers, -H 'Header1: val1' -H 'Header2: val2'
  -h, --help                  help for vhost
  -k, --no-tls-validation     Skip TLS certificate verification
  -P, --password string       Password for Basic Auth
  -p, --proxy string          Proxy to use for requests [http(s)://host:port]
      --timeout duration      HTTP Timeout (default 10s)
  -u, --url string            The target URL
  -a, --useragent string      Set the User-Agent string (default "gobuster/3.1.0")
  -U, --username string       Username for Basic Auth
​
Global Flags:
  -z, --no-progress       Don't display progress
  -o, --output string     Output file to write results to (defaults to stdout)
  -q, --quiet             Don't print the banner and other noise
  -t, --threads int       Number of concurrent threads (default 10)
      --delay duration    Time each thread waits between requests (e.g. 1500ms)
  -v, --verbose           Verbose output (errors)
  -w, --wordlist string   Path to the wordlist
​
vhost Model Example Command Line:
gobuster vhost -u https://mysite.com -w common-vhosts.txt
Details reference link:​
enum4linux
Enum4linux is a tool for enumerating information from Windows and Samba systems. It attempts to offer similar functionality to enum.exe formerly available from www.bindview.com.
Installation:
kali@kali#sudo apt update
kali@kali#sudo apt install enum4linux
Details reference link:​
Automatic Recon
nmapAutomator
nmapAutomator is an automated nmap scan tool and is easy to use. Please install the required tools before your installations from the link :.
Installation:
kali@kali#sudo git clone https://github.com/21y4d/nmapAutomator.git 
kali@kali#sudo ln -s $(pwd)/nmapAutomator/nmapAutomator.sh /usr/local/bin/
Usage Example:
autorecon 10.10.10.5
autorecon -v 10.10.10.5
autorecon -vv 10.10.10.5
note: atom tool will be a good one for reading autorecon scan records.
Usage:
./nmapAutomator.sh -h
Usage: nmapAutomator.sh -H/--host <TARGET-IP> -t/--type <TYPE>
Optional: [-r/--remote <REMOTE MODE>] [-d/--dns <DNS SERVER>] [-o/--output <OUTPUT DIRECTORY>] [-s/--static-nmap <STATIC NMAP PATH>]
​
Scan Types:
	Network : Shows all live hosts in the host's network (~15 seconds)
	Port    : Shows all open ports (~15 seconds)
	Script  : Runs a script scan on found ports (~5 minutes)
	Full    : Runs a full range port scan, then runs a thorough scan on new ports (~5-10 minutes)
	UDP     : Runs a UDP scan "requires sudo" (~5 minutes)
	Vulns   : Runs CVE scan and nmap Vulns scan on all found ports (~5-15 minutes)
	Recon   : Suggests recon commands, then prompts to automatically run them
	All     : Runs all the scans (~20-30 minutes)
Example scans:
./nmapAutomator.sh --host 10.10.10.5 --type All
./nmapAutomator.sh -H 10.10.10.5 -t Basic
./nmapAutomator.sh -H devel.htb -t Recon -d 1.1.1.1
./nmapAutomator.sh -H 10.10.10.5 -t network -s ./nmap
AutoRecon
AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services. AutoRecon uses Python 3 specific functionality and does not support Python 2.The details reference link:​
Usage:
usage: autorecon [-t TARGET_FILE] [-p PORTS] [-m MAX_SCANS] [-mp MAX_PORT_SCANS] [-c CONFIG_FILE] [-g GLOBAL_FILE]
                 [--tags TAGS] [--exclude-tags TAGS] [--port-scans PLUGINS] [--service-scans PLUGINS]
                 [--reports PLUGINS] [--plugins-dir PLUGINS_DIR] [--add-plugins-dir PLUGINS_DIR] [-l [TYPE]]
                 [-o OUTPUT] [--single-target] [--only-scans-dir] [--create-port-dirs] [--heartbeat HEARTBEAT]
                 [--timeout TIMEOUT] [--target-timeout TARGET_TIMEOUT] [--nmap NMAP | --nmap-append NMAP_APPEND]
                 [--proxychains] [--disable-sanity-checks] [--disable-keyboard-control]
                 [--force-services SERVICE [SERVICE ...]] [--accessible] [-v] [--version] [--curl.path VALUE]
                 [--dirbuster.tool {feroxbuster,gobuster,dirsearch,ffuf,dirb}]
                 [--dirbuster.wordlist VALUE [VALUE ...]] [--dirbuster.threads VALUE] [--dirbuster.ext VALUE]
                 [--onesixtyone.community-strings VALUE] [--global.username-wordlist VALUE]
                 [--global.password-wordlist VALUE] [--global.domain VALUE] [-h]
                 [targets ...]
​
Network reconnaissance tool to port scan and automatically enumerate services found on multiple targets.
​
positional arguments:
  targets               IP addresses (e.g. 10.0.0.1), CIDR notation (e.g. 10.0.0.1/24), or resolvable hostnames (e.g.
                        foo.bar) to scan.
​
optional arguments:
  -t TARGET_FILE, --target-file TARGET_FILE
                        Read targets from file.
  -p PORTS, --ports PORTS
                        Comma separated list of ports / port ranges to scan. Specify TCP/UDP ports by prepending list
                        with T:/U: To scan both TCP/UDP, put port(s) at start or specify B: e.g.
                        53,T:21-25,80,U:123,B:123. Default: None
  -m MAX_SCANS, --max-scans MAX_SCANS
                        The maximum number of concurrent scans to run. Default: 50
  -mp MAX_PORT_SCANS, --max-port-scans MAX_PORT_SCANS
                        The maximum number of concurrent port scans to run. Default: 10 (approx 20% of max-scans unless
                        specified)
  -c CONFIG_FILE, --config CONFIG_FILE
                        Location of AutoRecon's config file. Default: ~/.config/AutoRecon/config.toml
  -g GLOBAL_FILE, --global-file GLOBAL_FILE
                        Location of AutoRecon's global file. Default: ~/.config/AutoRecon/global.toml
  --tags TAGS           Tags to determine which plugins should be included. Separate tags by a plus symbol (+) to group
                        tags together. Separate groups with a comma (,) to create multiple groups. For a plugin to be
                        included, it must have all the tags specified in at least one group. Default: default
  --exclude-tags TAGS   Tags to determine which plugins should be excluded. Separate tags by a plus symbol (+) to group
                        tags together. Separate groups with a comma (,) to create multiple groups. For a plugin to be
                        excluded, it must have all the tags specified in at least one group. Default: None
  --port-scans PLUGINS  Override --tags / --exclude-tags for the listed PortScan plugins (comma separated). Default:
                        None
  --service-scans PLUGINS
                        Override --tags / --exclude-tags for the listed ServiceScan plugins (comma separated). Default:
                        None
  --reports PLUGINS     Override --tags / --exclude-tags for the listed Report plugins (comma separated). Default: None
  --plugins-dir PLUGINS_DIR
                        The location of the plugins directory. Default: ~/.config/AutoRecon/plugins
  --add-plugins-dir PLUGINS_DIR
                        The location of an additional plugins directory to add to the main one. Default: None
  -l [TYPE], --list [TYPE]
                        List all plugins or plugins of a specific type. e.g. --list, --list port, --list service
  -o OUTPUT, --output OUTPUT
                        The output directory for results. Default: results
  --single-target       Only scan a single target. A directory named after the target will not be created. Instead, the
                        directory structure will be created within the output directory. Default: False
  --only-scans-dir      Only create the "scans" directory for results. Other directories (e.g. exploit, loot, report)
                        will not be created. Default: False
  --create-port-dirs    Create directories for ports within the "scans" directory (e.g. scans/tcp80, scans/udp53) and
                        store results in these directories. Default: True
  --heartbeat HEARTBEAT
                        Specifies the heartbeat interval (in seconds) for scan status messages. Default: 60
  --timeout TIMEOUT     Specifies the maximum amount of time in minutes that AutoRecon should run for. Default: None
  --target-timeout TARGET_TIMEOUT
                        Specifies the maximum amount of time in minutes that a target should be scanned for before
                        abandoning it and moving on. Default: None
  --nmap NMAP           Override the {nmap_extra} variable in scans. Default: -vv --reason -Pn
  --nmap-append NMAP_APPEND
                        Append to the default {nmap_extra} variable in scans. Default: -T4
  --proxychains         Use if you are running AutoRecon via proxychains. Default: False
  --disable-sanity-checks
                        Disable sanity checks that would otherwise prevent the scans from running. Default: False
  --disable-keyboard-control
                        Disables keyboard control ([s]tatus, Up, Down) if you are in SSH or Docker.
  --force-services SERVICE [SERVICE ...]
                        A space separated list of services in the following style: tcp/80/http tcp/443/https/secure
  --accessible          Attempts to make AutoRecon output more accessible to screenreaders. Default: False
  -v, --verbose         Enable verbose output. Repeat for more verbosity.
  --version             Prints the AutoRecon version and exits.
  -h, --help            Show this help message and exit.
​
plugin arguments:
  These are optional arguments for certain plugins.
​
  --curl.path VALUE     The path on the web server to curl. Default: /
  --dirbuster.tool {feroxbuster,gobuster,dirsearch,ffuf,dirb}
                        The tool to use for directory busting. Default: feroxbuster
  --dirbuster.wordlist VALUE [VALUE ...]
                        The wordlist(s) to use when directory busting. Separate multiple wordlists with spaces. Default:
                        ['/usr/share/seclists/Discovery/Web-Content/common.txt', '/usr/share/seclists/Discovery/Web-
                        Content/big.txt', '/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt']
  --dirbuster.threads VALUE
                        The number of threads to use when directory busting. Default: 10
  --dirbuster.ext VALUE
                        The extensions you wish to fuzz (no dot, comma separated). Default: txt,html,php,asp,aspx,jsp
  --onesixtyone.community-strings VALUE
                        The file containing a list of community strings to try. Default:
                        /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt
​
global plugin arguments:
  These are optional arguments that can be used by all plugins.
​
  --global.username-wordlist VALUE
                        A wordlist of usernames, useful for bruteforcing. Default: /usr/share/seclists/Usernames/top-
                        usernames-shortlist.txt
  --global.password-wordlist VALUE
                        A wordlist of passwords, useful for bruteforcing. Default:
                        /usr/share/seclists/Passwords/darkweb2017-top100.txt
  --global.domain VALUE
                        The domain to use (if known). Used for DNS and/or Active Directory. Default: None
​
