import sys
import argparse
import subprocess
import os
import time
import random
import threading
import re
import random
from urllib.parse import urlsplit

CURSOR_UP_ONE = '\x1b[1A' 
ERASE_LINE = '\x1b[2K'

# Scan Time Elapser
intervals = (
    ('h', 3600),
    ('m', 60),
    ('s', 1),
    )
def display_time(seconds, granularity=3):
    result = []
    seconds = seconds + 1
    for name, count in intervals:
        value = seconds // count
        if value:
            seconds -= value * count
            result.append("{}{}".format(value, name))
    return ' '.join(result[:granularity])

def terminal_size():
    try:
        rows, columns = subprocess.check_output(['stty', 'size']).split()
        return int(columns)
    except subprocess.CalledProcessError as e:
        return int(20)
    
def url_maker(url):
    if not re.match(r'http(s?)\:', url):
        url = 'http://' + url
    parsed = urlsplit(url)
    host = parsed.netloc
    if host.startswith('www.'):
        host = host[4:]
    return host

def check_internet():
    os.system('ping -c1 github.com > rs_net 2>&1')
    if "0% packet loss" in open('rs_net').read():
        val = 1
    else:
        val = 0
    os.system('rm rs_net > /dev/null 2>&1')
    return val

# Initializing the color module class
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    BADFAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    BG_ERR_TXT  = '\033[41m' # For critical errors and crashes
    BG_HEAD_TXT = '\033[100m'
    BG_ENDL_TXT = '\033[46m'
    BG_CRIT_TXT = '\033[45m'
    BG_HIGH_TXT = '\033[41m'
    BG_MED_TXT  = '\033[43m'
    BG_LOW_TXT  = '\033[44m'
    BG_INFO_TXT = '\033[42m'

    BG_SCAN_TXT_START = '\x1b[6;30;42m'
    BG_SCAN_TXT_END   = '\x1b[0m'

# Classifies the Vulnerability's Severity
def vul_info(val):
    result =''
    if val == 'c':
        result = bcolors.BG_CRIT_TXT+" critical "+bcolors.ENDC
    elif val == 'h':
        result = bcolors.BG_HIGH_TXT+" high "+bcolors.ENDC
    elif val == 'm':
        result = bcolors.BG_MED_TXT+" medium "+bcolors.ENDC
    elif val == 'l':
        result = bcolors.BG_LOW_TXT+" low "+bcolors.ENDC
    else:
        result = bcolors.BG_INFO_TXT+" info "+bcolors.ENDC
    return result

# Legends
proc_high = bcolors.BADFAIL + "●" + bcolors.ENDC
proc_med  = bcolors.WARNING + "●" + bcolors.ENDC
proc_low  = bcolors.OKGREEN + "●" + bcolors.ENDC

# Links the vulnerability with threat level and remediation database
def vul_remed_info(v1,v2,v3):
    print(bcolors.BOLD+"Dreigingsniveau van kwetsbaarheid"+bcolors.ENDC)
    print("\t"+vul_info(v2)+" "+bcolors.WARNING+str(tool_resp[v1][0])+bcolors.ENDC)
    print(bcolors.BOLD+"Definitie van kwetsbaarheid"+bcolors.ENDC)
    print("\t"+bcolors.BADFAIL+str(tools_fix[v3-1][1])+bcolors.ENDC)
    print(bcolors.BOLD+"Herstel van kwetsbaarheid"+bcolors.ENDC)
    print("\t"+bcolors.OKGREEN+str(tools_fix[v3-1][2])+bcolors.ENDC)

# dnsScan Help Context
def helper():
        print(bcolors.OKBLUE+"Informatie:"+bcolors.ENDC)
        print("------------")
        print("\t./vuln-scan.py example.com: Scans de domein example.com.")
        print("\t./vuln-scan.py example.com --skip dmitry --skip theHarvester: Skip de 'dmitry' en 'theHarvester' tests.")
        print("\t./vuln-scan.py example.com --nospinner: Zet de idle loader/spinner uit.")
        print("\t./vuln-scan.py --help     : Weergeeft de help context.")
        print(bcolors.OKBLUE+"Interactief:"+bcolors.ENDC)
        print("------------")
        print("\tCtrl+C: Slaat huidige test over.")
        print("\tCtrl+Z: Sluit vuln-scan af.")
        print(bcolors.OKBLUE+"Legends:"+bcolors.ENDC)
        print("--------")
        print("\t["+proc_high+"]: Scan process may take longer times (not predictable).")
        print("\t["+proc_med+"]: Scan process may take less than 10 minutes.")
        print("\t["+proc_low+"]: Scan process may take less than a minute or two.")
        print(bcolors.OKBLUE+"Kwetsbaarheidsinformatie:"+bcolors.ENDC)
        print("--------------------------")
        print("\t"+vul_info('c')+": Vereist onmiddellijke aandacht, omdat dit kan leiden tot compromissen of onbeschikbaarheid van de dienst.")
        print("\t"+vul_info('h')+"    : Leidt misschien niet tot een onmiddellijk compromis, maar er zijn aanzienlijke kansen op waarschijnlijkheid.")
        print("\t"+vul_info('m')+"  : De aanvaller kan meerdere kwetsbaarheden van dit type met elkaar in verband brengen om een ​​geavanceerde aanval uit te voeren.")
        print("\t"+vul_info('l')+"     : Geen ernstig probleem, maar het wordt aanbevolen om de bevinding te verzorgen.")
        print("\t"+vul_info('i')+"    : Niet geclassificeerd als een kwetsbaarheid, gewoon een nuttige informatieve waarschuwing om in overweging te nemen.\n")

# Clears Line
def clear():
        sys.stdout.write("\033[F")
        sys.stdout.write("\033[K") #clears until EOL

# dnsScan Logo
def logo():
    print(bcolors.WARNING)
    logo_ascii = """
 ___ _____    _____   _    _  _______ _   _ 
|_ _|_   _|  |__  /  / \  | |/ / ____| \ | |
 | |  | |_____ / /  / _ \ | ' /|  _| |  \| |
 | |  | |_____/ /_ / ___ \| . \| |___| |\  |
|___| |_|    /____/_/   \_\_|\_\_____|_| \_|

"""
    print(logo_ascii)
    print(bcolors.ENDC)


# Initiliazing the idle loader/spinner class
class Spinner:
    busy = False
    delay = 0.005 # 0.05

    @staticmethod
    def spinning_cursor():
        while 1:
            for cursor in ' ': yield cursor
    def __init__(self, delay=None):
        self.spinner_generator = self.spinning_cursor()
        if delay and float(delay): self.delay = delay
        self.disabled = False

    def spinner_task(self):
        inc = 0
        try:
            while self.busy:
                if not self.disabled:
                    x = bcolors.BG_SCAN_TXT_START+next(self.spinner_generator)+bcolors.BG_SCAN_TXT_END
                    inc = inc + 1
                    print(x,end='')
                    if inc>random.uniform(0,terminal_size()): #30 init
                        print(end="\r")
                        bcolors.BG_SCAN_TXT_START = '\x1b[6;30;'+str(round(random.uniform(40,47)))+'m'
                        inc = 0
                    sys.stdout.flush()
                time.sleep(self.delay)
                if not self.disabled:
                    sys.stdout.flush()

        except (KeyboardInterrupt, SystemExit):
            print("\n\t"+ bcolors.BG_ERR_TXT+"DNS-scan received a series of Ctrl+C hits. Quitting..." +bcolors.ENDC)
            sys.exit(1)

    def start(self):
        self.busy = True
        try:
            threading.Thread(target=self.spinner_task).start()
        except Exception as e:
            print("\n")
        
    def stop(self):
        try:
            self.busy = False
            time.sleep(self.delay)
        except (KeyboardInterrupt, SystemExit):
            print("\n\t"+ bcolors.BG_ERR_TXT+"DNS-Scan received a series of Ctrl+C hits. Quitting..." +bcolors.ENDC)
            sys.exit(1)

# End ofloader/spinner class

# Instantiating the spinner/loader class
spinner = Spinner()

# Scanners that will be used and filename rotation (default: enabled (1))
tool_names = [
                #1
                ["host","Host - Controlen op bestaan van IPV6-adres.","host",1],

                #2
                ["aspnet_config_err","ASP.Net Misconfiguratie - Controleert op ASP.Net Misconfiguratie.","wget",1],

                #3
                ["wp_check","WordPress Checker - Controles voor WordPress-installatie.","wget",1],

                #4
                ["drp_check", "Drupal Checker - Controles voor Drupal-installatie.","wget",1],

                #5
                ["joom_check", "Joomla Checker - Controleert op Joomla-installatie.","wget",1],

                #6
                ["uniscan","Uniscan - Controles op robots.txt & sitemap.xml","uniscan",1],

                #7
                ["wafw00f","Wafw00f - Controles voor applicatie-firewalls.","wafw00f",1],

                #8
                ["nmap","Nmap - Fast Scan [Only Few Port Checks]","nmap",1],

                #9
                ["theHarvester","The Harvester - Scant op e-mails met de passieve zoekfunctie van Google.","theHarvester",1],

                #10
                ["dnsrecon","DNSRecon - Pogingen om meerdere zones over te dragen op naamservers.","dnsrecon",1],

                #11
                #["fierce","Fierce - Attempts Zone Transfer [No Brute Forcing]","fierce",1],

                #12
                ["dnswalk","DNSWalk - Pogingen Zone Transfer.","dnswalk",1],

                #13
                ["whois","WHOis - Controles voor de contactgegevens van de beheerder.","whois",1],

                #14
                ["nmap_header","Nmap [XSS Filter Check] - Controleert of XSS Protection Header aanwezig is.","nmap",1],

                #15
                ["nmap_sloris","Nmap [Slowloris DoS] - Controles op een denial-of-service-kwetsbaarheid van Slowloris.","nmap",1],

                #16
                ["sslyze_hbleed","SSLyze - Controleert alleen op Heartbleed-kwetsbaarheid.","sslyze",1],

                #17
                ["nmap_hbleed","Nmap [Heartbleed] - Controleert alleen op Heartbleed-kwetsbaarheid.","nmap",1],

                #18
                ["nmap_poodle","Nmap [POODLE] - Controleert alleen op Poodle-kwetsbaarheid.","nmap",1],

                #19
                ["nmap_ccs","Nmap [OpenSSL CCS Injection] - Controleert alleen voor CCS-injectie.","nmap",1],

                #20
                ["nmap_freak","Nmap [FREAK] - Controleert alleen op FREAK-kwetsbaarheid.","nmap",1],

                #21
                ["nmap_logjam","Nmap [LOGJAM] - Controles op LOGJAM-kwetsbaarheid.","nmap",1],

                #22
                ["sslyze_ocsp","SSLyze - Controles voor OCSP-nieten.","sslyze",1],

                #23
                ["sslyze_zlib","SSLyze - Controles voor ZLib Deflate-compressie.","sslyze",1],

                #24
                ["sslyze_reneg","SSLyze - Controles voor veilige heronderhandelingsondersteuning en klantheronderhandeling.","sslyze",1],

                #25
                ["sslyze_resum","SSLyze - Controles voor ondersteuning voor sessiehervatting met [Session IDs/TLS Tickets].","sslyze",1],

                #26
                ["lbd","LBD - Controleert op DNS/HTTP Load Balancers.","lbd",1],

                #27
                ["golismero_dns_malware","Golismero - Controleert of het domein is spoofed of hijacked.","golismero",1],

                #28
                ["golismero_heartbleed","Golismero - Controleert alleen op Heartbleed-kwetsbaarheid.","golismero",1],

                #29
                ["golismero_brute_url_predictables","Golismero - BruteForces voor bepaalde bestanden op het domein.","golismero",1],

                #30
                ["golismero_brute_directories","Golismero - BruteForces voor bepaalde mappen op het domein.","golismero",1],

                #31
                ["golismero_sqlmap","Golismero - SQLMap [Retrieves only the DB Banner]","golismero",1],

                #32
                ["dirb","DirB - Brutes het doelwit voor Open Directory's.","dirb",1],

                #33
                ["xsser","XSSer - Controle voor Cross-Site Scripting [XSS] Attacks.","xsser",1],

                #34
                ["golismero_ssl_scan","Golismero SSL Scans - Voert SSL-gerelateerde scans uit.","golismero",1],

                #35
                ["golismero_zone_transfer","Golismero Zone Transfer - Pogingen Zone Transfer.","golismero",1],

                #36
                ["golismero_nikto","Golismero Nikto Scans - Gebruikt Nikto Plugin om kwetsbaarheden te detecteren.","golismero",1],

                #37
                ["golismero_brute_subdomains","Golismero Subdomains Bruter - Brute Forces Subdomein ontdekken.","golismero",1],

                #38
                ["dnsenum_zone_transfer","DNSEnum - Pogingen Zone Transfer.","dnsenum",1],

                #39
                ["fierce_brute_subdomains","Fierce Subdomains Bruter - Brute Forces Subdomein ontdekken.","fierce",1],

                #40
                ["dmitry_email","DMitry - Verzamelt passief e-mails van het domein.","dmitry",1],

                #41
                ["dmitry_subdomains","DMitry - Verzamelt passief subdomeinen van het domein.","dmitry",1],

                #42
                ["nmap_telnet","Nmap [TELNET] - Controleert of de TELNET-service actief is.","nmap",1],

                #43
                ["nmap_ftp","Nmap [FTP] - Controleert of de FTP-service actief is.","nmap",1],

                #44
                ["nmap_stuxnet","Nmap [STUXNET] - Controleert of de host wordt beïnvloed door STUXNET Worm.","nmap",1],

                #45
                ["webdav","WebDAV - Controleert of WEBDAV is ingeschakeld in de Home directory.","davtest",1],

                #46
                ["golismero_finger","Golismero - Voltooid een fingerprint op het domein.","golismero",1],

                #47
                ["uniscan_filebrute","Uniscan - Brutes voor bestandsnamen op het domein.","uniscan",1],

                #48
                ["uniscan_dirbrute", "Uniscan - Brutes Directory's op het domein.","uniscan",1],

                #49
                ["uniscan_ministresser", "Uniscan - Stress test het domein.","uniscan",1],

                #50
                ["uniscan_rfi","Uniscan - Controles op LFI, RFI en RCE.","uniscan",1],

                #51
                ["uniscan_xss","Uniscan - Controles voor XSS, SQLi, BSQLi en andere controles.","uniscan",1],

                #52
                ["nikto_xss","Nikto - Controles voor Apache Verwacht XSS Header.","nikto",1],

                #53
                ["nikto_subrute","Nikto - Brute subdomeinen.","nikto",1],

                #54
                ["nikto_shellshock","Nikto - Controles op Shellshock-bug.","nikto",1],

                #55
                ["nikto_internalip","Nikto - Controles op intern IP-lek.","nikto",1],

                #56
                ["nikto_putdel","Nikto - Controles voor HTTP PUT DEL.","nikto",1],

                #57
                ["nikto_headers","Nikto - Controleert de domeinheaders.","nikto",1],

                #58
                ["nikto_ms01070","Nikto - Controles op MS10-070-beveiligingslek.","nikto",1],

                #59
                ["nikto_servermsgs","Nikto - Controles op serverproblemen.","nikto",1],

                #60
                ["nikto_outdated","Nikto - Controleert of de server verouderd is.","nikto",1],

                #61
                ["nikto_httpoptions","Nikto - Controles op HTTP-opties op het domein.","nikto",1],

                #62
                ["nikto_cgi","Nikto - Enumerates CGI Directories.","nikto",1],

                #63
                ["nikto_ssl","Nikto - Voert SSL-controles uit.","nikto",1],

                #64
                ["nikto_sitefiles","Nikto - Controleert op interessante bestanden op het domein.","nikto",1],

                #65
                ["nikto_paths","Nikto - Controles op injecteerbare paden.","nikto",1],

                #66
                ["dnsmap_brute","DNSMap - Brute subdomeinen.","dnsmap",1],

                #67
                ["nmap_sqlserver","Nmap - Controles voor MS-SQL Server DB","nmap",1],

                #68
                ["nmap_mysql", "Nmap - Controles voor MySQL DB","nmap",1],

                #69
                ["nmap_oracle", "Nmap - Controles voor ORACLE DB","nmap",1],

                #70
                ["nmap_rdp_udp","Nmap - Controles voor Remote Desktop Service via UDP","nmap",1],

                #71
                ["nmap_rdp_tcp","Nmap - Controles voor Remote Desktop Service via TCP","nmap",1],

                #72
                ["nmap_full_ps_tcp","Nmap - Voert een Full TCP Port Scan uit","nmap",1],

                #73
                ["nmap_full_ps_udp","Nmap - Voert een Full UDP Port Scan uit","nmap",1],

                #74
                ["nmap_snmp","Nmap - Controles voor SNMP-service","nmap",1],

                #75
                ["aspnet_elmah_axd","Controles voor ASP.net Elmah Logger","wget",1],

                #76
                ["nmap_tcp_smb","Controles voor SMB-service via TCP","nmap",1],

                #77
                ["nmap_udp_smb","Controles voor SMB-service via UDP","nmap",1],

                #78
                ["wapiti","Wapiti - Controles op SQLi, RCE, XSS en andere kwetsbaarheden","wapiti",1],

                #79
                ["nmap_iis","Nmap - Controles voor IIS WebDAV","nmap",1],

                #80
                ["whatweb","WhatWeb - Controles voor X-XSS Protection Header","whatweb",1],

                #81
                ["amass","AMass - Brutes-domein voor subdomeinen","amass",1]
            ]

# Command that is used to initiate the tool (with parameters and extra params)
tool_cmd   = [
                #1
                ["host ",""],

                #2
                ["wget -O /tmp/rapidscan_temp_aspnet_config_err --tries=1 ","/%7C~.aspx"],

                #3
                ["wget -O /tmp/rapidscan_temp_wp_check --tries=1 ","/wp-admin"],

                #4
                ["wget -O /tmp/rapidscan_temp_drp_check --tries=1 ","/user"],

                #5
                ["wget -O /tmp/rapidscan_temp_joom_check --tries=1 ","/administrator"],

                #6
                ["uniscan -e -u ",""],

                #7
                ["wafw00f ",""],

                #8
                ["nmap -F --open -Pn ",""],

                #9
                ["theHarvester -l 50 -b google -d ",""],

                #10
                ["dnsrecon -d ",""],

                #11
                #["fierce -wordlist xxx -dns ",""],

                #12
                ["dnswalk -d ","."],

                #13
                ["whois ",""],

                #14
                ["nmap -p80 --script http-security-headers -Pn ",""],

                #15
                ["nmap -p80,443 --script http-slowloris --max-parallelism 500 -Pn ",""],

                #16
                ["sslyze --heartbleed ",""],

                #17
                ["nmap -p443 --script ssl-heartbleed -Pn ",""],

                #18
                ["nmap -p443 --script ssl-poodle -Pn ",""],

                #19
                ["nmap -p443 --script ssl-ccs-injection -Pn ",""],

                #20
                ["nmap -p443 --script ssl-enum-ciphers -Pn ",""],

                #21
                ["nmap -p443 --script ssl-dh-params -Pn ",""],

                #22
                ["sslyze --certinfo=basic ",""],

                #23
                ["sslyze --compression ",""],

                #24
                ["sslyze --reneg ",""],

                #25
                ["sslyze --resum ",""],

                #26
                ["lbd ",""],

                #27
                ["golismero -e dns_malware scan ",""],

                #28
                ["golismero -e heartbleed scan ",""],

                #29
                ["golismero -e brute_url_predictables scan ",""],

                #30
                ["golismero -e brute_directories scan ",""],

                #31
                ["golismero -e sqlmap scan ",""],

                #32
                ["dirb http://"," -fi"],

                #33
                ["xsser --all=http://",""],

                #34
                ["golismero -e sslscan scan ",""],

                #35
                ["golismero -e zone_transfer scan ",""],

                #36
                ["golismero -e nikto scan ",""],

                #37
                ["golismero -e brute_dns scan ",""],

                #38
                ["dnsenum ",""],

                #39
                ["fierce --domain ",""],

                #40
                ["dmitry -e ",""],

                #41
                ["dmitry -s ",""],

                #42
                ["nmap -p23 --open -Pn ",""],

                #43
                ["nmap -p21 --open -Pn ",""],

                #44
                ["nmap --script stuxnet-detect -p445 -Pn ",""],

                #45
                ["davtest -url http://",""],

                #46
                ["golismero -e fingerprint_web scan ",""],

                #47
                ["uniscan -w -u ",""],

                #48
                ["uniscan -q -u ",""],

                #49
                ["uniscan -r -u ",""],

                #50
                ["uniscan -s -u ",""],

                #51
                ["uniscan -d -u ",""],

                #52
                ["nikto -Plugins 'apache_expect_xss' -host ",""],

                #53
                ["nikto -Plugins 'subdomain' -host ",""],

                #54
                ["nikto -Plugins 'shellshock' -host ",""],

                #55
                ["nikto -Plugins 'cookies' -host ",""],

                #56
                ["nikto -Plugins 'put_del_test' -host ",""],

                #57
                ["nikto -Plugins 'headers' -host ",""],

                #58
                ["nikto -Plugins 'ms10-070' -host ",""],

                #59
                ["nikto -Plugins 'msgs' -host ",""],

                #60
                ["nikto -Plugins 'outdated' -host ",""],

                #61
                ["nikto -Plugins 'httpoptions' -host ",""],

                #62
                ["nikto -Plugins 'cgi' -host ",""],

                #63
                ["nikto -Plugins 'ssl' -host ",""],

                #64
                ["nikto -Plugins 'sitefiles' -host ",""],

                #65
                ["nikto -Plugins 'paths' -host ",""],

                #66
                ["dnsmap ",""],

                #67
                ["nmap -p1433 --open -Pn ",""],

                #68
                ["nmap -p3306 --open -Pn ",""],

                #69
                ["nmap -p1521 --open -Pn ",""],

                #70
                ["nmap -p3389 --open -sU -Pn ",""],

                #71
                ["nmap -p3389 --open -sT -Pn ",""],

                #72
                ["nmap -p1-65535 --open -Pn ",""],

                #73
                ["nmap -p1-65535 -sU --open -Pn ",""],

                #74
                ["nmap -p161 -sU --open -Pn ",""],

                #75
                ["wget -O /tmp/rapidscan_temp_aspnet_elmah_axd --tries=1 ","/elmah.axd"],

                #76
                ["nmap -p445,137-139 --open -Pn ",""],

                #77
                ["nmap -p137,138 --open -Pn ",""],

                #78
                ["wapiti "," -f txt -o rapidscan_temp_wapiti"],

                #79
                ["nmap -p80 --script=http-iis-webdav-vuln -Pn ",""],
                
                #80
                ["whatweb "," -a 1"],

                #81
                ["amass enum -d ",""]
            ]

# Tool Responses (Begins) [Responses + Severity (c - critical | h - high | m - medium | l - low | i - informational) + Reference for Vuln Definition and Remediation]
tool_resp   = [
                #1
                ["Heeft geen IPv6-adres. Het is goed om er een te hebben.","i",1],

                #2
                ["ASP.Net is verkeerd geconfigureerd om server stack errors op het scherm te krijgen.","m",2],

                #3
                ["WordPress-installatie gevonden. Controleer op kwetsbaarheden komt overeen met die versie.","i",3],

                #4
                ["Drupal-installatie gevonden. Controleer op kwetsbaarheden komt overeen met die versie.","i",4],

                #5
                ["Joomla installatie gevonden. Controleer op kwetsbaarheden komt overeen met die versie.","i",5],

                #6
                ["robots.txt/sitemap.xml gevonden. Controleer die bestanden op informatie.","i",6],

                #7
                ["Geen firewall voor webapplicatie gedetecteerd","m",7],

                #8
                ["Sommige poorten zijn open. Voer handmatig een volledige scan uit.","l",8],

                #9
                ["E-mailadressen gevonden.","l",9],

                #10
                ["Zone Transfer Succesvol met DNSRecon. Configureer DNS onmiddellijk opnieuw.","h",10],

                #11
                #["Zone Transfer Successful using fierce. Reconfigure DNS immediately.","h",10],

                #12
                ["Zone Transfer Succesvol met dnswalk. Configureer DNS onmiddellijk opnieuw.","h",10],

                #13
                ["Whois-informatie openbaar beschikbaar.","i",11],

                #14
                ["XSS-beschermingsfilter is uitgeschakeld.","m",12],

                #15
                ["Kwetsbaar voor Slowloris Denial of Service.","c",13],

                #16
                ["HEARTBLEED-kwetsbaarheid gevonden met SSLyze.","h",14],

                #17
                ["HEARTBLEED-kwetsbaarheid gevonden met Nmap.","h",14],

                #18
                ["POODLE-kwetsbaarheid gedetecteerd.","h",15],

                #19
                ["OpenSSL CCS-injectie gedetecteerd.","h",16],

                #20
                ["FREAK kwetsbaarheid gedetecteerd.","h",17],

                #21
                ["LOGJAM-kwetsbaarheid gedetecteerd.","h",18],

                #22
                ["Onsuccesvolle OCSP-reactie.","m",19],

                #23
                ["Server ondersteunt Deflate Compression.","m",20],

                #24
                ["Beveiligde door de klant geïnitieerde heronderhandeling wordt ondersteund.","m",21],

                #25
                ["Veilige hervatting niet ondersteund met (sessie-ID's/TLS-tickets).","m",22],

                #26
                ["Geen op DNS/HTTP gebaseerde load balancers gevonden.","l",23],

                #27
                ["Domein is spoofed/hijacked.","h",24],

                #28
                ["HEARTBLEED-kwetsbaarheid gevonden met Golismero.","h",14],

                #29
                ["Open bestanden gevonden met Golismero BruteForce.","m",25],

                #30
                ["Open mappen gevonden met Golismero BruteForce.","m",26],

                #31
                ["DB Banner opgehaald met SQLMap.","l",27],

                #32
                ["Open mappen gevonden met DirB.","m",26],

                #33
                ["XSSer heeft XSS-kwetsbaarheden gevonden.","c",28],

                #34
                ["SSL-gerelateerde kwetsbaarheden gevonden met Golismero.","m",29],

                #35
                ["Zoneoverdracht succesvol met Golismero. Configureer DNS onmiddellijk opnieuw.","h",10],

                #36
                ["Golismero Nikto Plugin heeft kwetsbaarheden gevonden.","m",30],

                #37
                ["Subdomeinen gevonden met Golismero.","m",31],

                #38
                ["Zone Transfer Succesvol met DNSEnum. Configureer DNS onmiddellijk opnieuw.","h",10],

                #39
                ["Subdomeinen gevonden met Fierce.","m",31],

                #40
                ["E-mailadressen ontdekt met DMitry.","l",9],

                #41
                ["Subdomeinen ontdekt met DMitry.","m",31],

                #42
                ["Telnet-service gedetecteerd.","h",32],

                #43
                ["FTP-service gedetecteerd.","c",33],

                #44
                ["Kwetsbaar voor STUXNET.","c",34],

                #45
                ["WebDAV ingeschakeld.","m",35],

                #46
                ["Informatie gevonden via Fingerprinting.","l",36],

                #47
                ["Open bestanden gevonden met Uniscan.","m",25],

                #48
                ["Open mappen gevonden met Uniscan.","m",26],

                #49
                ["Kwetsbaar voor stresstests.","h",37],

                #50
                ["Uniscan heeft mogelijke LFI, RFI of RCE gedetecteerd.","h",38],

                #51
                ["Uniscan heeft mogelijke XSS, SQLi, BSQLi gedetecteerd.","h",39],

                #52
                ["Apache verwacht XSS-header niet aanwezig.","m",12],

                #53
                ["Subdomeinen gevonden met Nikto.","m",31],

                #54
                ["Webserver kwetsbaar voor Shellshock Bug.","c",40],

                #55
                ["Webserver lekt interne IP.","l",41],

                #56
                ["HTTP PUT DEL-methoden ingeschakeld.","m",42],

                #57
                ["Enkele kwetsbare headers zichtbaar.","m",43],

                #58
                ["Webserver kwetsbaar voor MS10-070.","h",44],

                #59
                ["Enkele problemen gevonden op de webserver.","m",30],

                #60
                ["Webserver is verouderd.","h",45],

                #61
                ["Sommige problemen gevonden met HTTP-opties.","l",42],

                #62
                ["CGI-directories opgesomd.","l",26],

                #63
                ["Kwetsbaarheden gemeld in SSL-scans.","m",29],

                #64
                ["Interessante bestanden gedetecteerd.","m",25],

                #65
                ["Injecteerbare Paths gedetecteerd.","l",46],

                #66
                ["Gevonden subdomeinen met DNSMap.","m",31],

                #67
                ["MS-SQL DB-service gedetecteerd.","l",47],

                #68
                ["MySQL DB-service gedetecteerd.","l",47],

                #69
                ["ORACLE DB-service gedetecteerd.","l",47],

                #70
                ["RDP-server gedetecteerd via UDP.","h",48],

                #71
                ["RDP-server gedetecteerd via TCP.","h",48],

                #72
                ["TCP-poorten zijn open","l",8],

                #73
                ["UDP-poorten zijn open","l",8],

                #74
                ["SNMP-service gedetecteerd.","m",49],

                #75
                ["Elmah is geconfigureerd.","m",50],

                #76
                ["SMB-poorten zijn open via TCP","m",51],

                #77
                ["SMB-poorten zijn open via UDP","m",51],

                #78
                ["Wapiti ontdekte een reeks kwetsbaarheden","h",30],

                #79
                ["IIS WebDAV is ingeschakeld","m",35],

                #80
                ["X-XSS-beveiliging is niet aanwezig","m",12],

                #81
                ["Gevonden subdomeinen met AMass","m",31]
            ]

# Tool Responses (Ends)

# Tool Status (Response Data + Response Code (if status check fails and you still got to push it + Legends + Approx Time + Tool Identification + Bad Responses)
tool_status = [
                #1
                ["has IPv6",1,proc_low," < 15s","ipv6",["not found","has IPv6"]],

                #2
                ["Server Error",0,proc_low," < 30s","asp.netmisconf",["unable to resolve host address","Connection timed out"]],

                #3
                ["wp-login",0,proc_low," < 30s","wpcheck",["unable to resolve host address","Connection timed out"]],

                #4
                ["drupal",0,proc_low," < 30s","drupalcheck",["unable to resolve host address","Connection timed out"]],

                #5
                ["joomla",0,proc_low," < 30s","joomlacheck",["unable to resolve host address","Connection timed out"]],

                #6
                ["[+]",0,proc_low," < 40s","robotscheck",["Use of uninitialized value in unpack at"]],

                #7
                ["No WAF",0,proc_low," < 45s","wafcheck",["appears to be down"]],

                #8
                ["tcp open",0,proc_med," <  2m","nmapopen",["Failed to resolve"]],

                #9
                ["No emails found",1,proc_med," <  3m","harvester",["No hosts found","No emails found"]],

                #10
                ["[+] Zone Transfer was successful!!",0,proc_low," < 20s","dnsreconzt",["Could not resolve domain"]],

                #11
                #["Whoah, it worked",0,proc_low," < 30s","fiercezt",["none"]],

                #12
                ["0 errors",0,proc_low," < 35s","dnswalkzt",["!!!0 failures, 0 warnings, 3 errors."]],

                #13
                ["Admin Email:",0,proc_low," < 25s","whois",["No match for domain"]],

                #14
                ["XSS filter is disabled",0,proc_low," < 20s","nmapxssh",["Failed to resolve"]],

                #15
                ["VULNERABLE",0,proc_high," < 45m","nmapdos",["Failed to resolve"]],

                #16
                ["Server is vulnerable to Heartbleed",0,proc_low," < 40s","sslyzehb",["Could not resolve hostname"]],

                #17
                ["VULNERABLE",0,proc_low," < 30s","nmap1",["Failed to resolve"]],

                #18
                ["VULNERABLE",0,proc_low," < 35s","nmap2",["Failed to resolve"]],

                #19
                ["VULNERABLE",0,proc_low," < 35s","nmap3",["Failed to resolve"]],

                #20
                ["VULNERABLE",0,proc_low," < 30s","nmap4",["Failed to resolve"]],

                #21
                ["VULNERABLE",0,proc_low," < 35s","nmap5",["Failed to resolve"]],

                #22
                ["ERROR - OCSP response status is not successful",0,proc_low," < 25s","sslyze1",["Could not resolve hostname"]],

                #23
                ["VULNERABLE",0,proc_low," < 30s","sslyze2",["Could not resolve hostname"]],

                #24
                ["VULNERABLE",0,proc_low," < 25s","sslyze3",["Could not resolve hostname"]],

                #25
                ["VULNERABLE",0,proc_low," < 30s","sslyze4",["Could not resolve hostname"]],

                #26
                ["does NOT use Load-balancing",0,proc_med," <  4m","lbd",["NOT FOUND"]],

                #27
                ["No vulnerabilities found",1,proc_low," < 45s","golism1",["Cannot resolve domain name","No vulnerabilities found"]],

                #28
                ["No vulnerabilities found",1,proc_low," < 40s","golism2",["Cannot resolve domain name","No vulnerabilities found"]],

                #29
                ["No vulnerabilities found",1,proc_low," < 45s","golism3",["Cannot resolve domain name","No vulnerabilities found"]],

                #30
                ["No vulnerabilities found",1,proc_low," < 40s","golism4",["Cannot resolve domain name","No vulnerabilities found"]],

                #31
                ["No vulnerabilities found",1,proc_low," < 45s","golism5",["Cannot resolve domain name","No vulnerabilities found"]],

                #32
                ["FOUND: 0",1,proc_high," < 35m","dirb",["COULDNT RESOLVE HOST","FOUND: 0"]],

                #33
                ["Could not find any vulnerability!",1,proc_med," <  4m","xsser",["XSSer is not working propertly!","Could not find any vulnerability!"]],

                #34
                ["Occurrence ID",0,proc_low," < 45s","golism6",["Cannot resolve domain name"]],

                #35
                ["DNS zone transfer successful",0,proc_low," < 30s","golism7",["Cannot resolve domain name"]],

                #36
                ["Nikto found 0 vulnerabilities",1,proc_med," <  4m","golism8",["Cannot resolve domain name","Nikto found 0 vulnerabilities"]],

                #37
                ["Possible subdomain leak",0,proc_high," < 30m","golism9",["Cannot resolve domain name"]],

                #38
                ["AXFR record query failed:",1,proc_low," < 45s","dnsenumzt",["NS record query failed:","AXFR record query failed","no NS record for"]],

                #39
                ["Found 0 entries",1,proc_high," < 75m","fierce2",["Found 0 entries","is gimp"]],

                #40
                ["Found 0 E-Mail(s)",1,proc_low," < 30s","dmitry1",["Unable to locate Host IP addr","Found 0 E-Mail(s)"]],

                #41
                ["Found 0 possible subdomain(s)",1,proc_low," < 35s","dmitry2",["Unable to locate Host IP addr","Found 0 possible subdomain(s)"]],

                #42
                ["open",0,proc_low," < 15s","nmaptelnet",["Failed to resolve"]],

                #43
                ["open",0,proc_low," < 15s","nmapftp",["Failed to resolve"]],

                #44
                ["open",0,proc_low," < 20s","nmapstux",["Failed to resolve"]],

                #45
                ["SUCCEED",0,proc_low," < 30s","webdav",["is not DAV enabled or not accessible."]],

                #46
                ["No vulnerabilities found",1,proc_low," < 15s","golism10",["Cannot resolve domain name","No vulnerabilities found"]],

                #47
                ["[+]",0,proc_med," <  2m","uniscan2",["Use of uninitialized value in unpack at"]],

                #48
                ["[+]",0,proc_med," <  5m","uniscan3",["Use of uninitialized value in unpack at"]],

                #49
                ["[+]",0,proc_med," <  9m","uniscan4",["Use of uninitialized value in unpack at"]],

                #50
                ["[+]",0,proc_med," <  8m","uniscan5",["Use of uninitialized value in unpack at"]],

                #51
                ["[+]",0,proc_med," <  9m","uniscan6",["Use of uninitialized value in unpack at"]],

                #52
                ["0 item(s) reported",1,proc_low," < 35s","nikto1",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #53
                ["0 item(s) reported",1,proc_low," < 35s","nikto2",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #54
                ["0 item(s) reported",1,proc_low," < 35s","nikto3",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #55
                ["0 item(s) reported",1,proc_low," < 35s","nikto4",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #56
                ["0 item(s) reported",1,proc_low," < 35s","nikto5",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #57
                ["0 item(s) reported",1,proc_low," < 35s","nikto6",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #58
                ["0 item(s) reported",1,proc_low," < 35s","nikto7",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #59
                ["0 item(s) reported",1,proc_low," < 35s","nikto8",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #60
                ["0 item(s) reported",1,proc_low," < 35s","nikto9",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #61
                ["0 item(s) reported",1,proc_low," < 35s","nikto10",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #62
                ["0 item(s) reported",1,proc_low," < 35s","nikto11",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #63
                ["0 item(s) reported",1,proc_low," < 35s","nikto12",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #64
                ["0 item(s) reported",1,proc_low," < 35s","nikto13",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #65
                ["0 item(s) reported",1,proc_low," < 35s","nikto14","ERROR: Cannot resolve hostname , 0 item(s) reported"],

                #66
                ["#1",0,proc_high," < 30m","dnsmap_brute",["[+] 0 (sub)domains and 0 IP address(es) found"]],

                #67
                ["open",0,proc_low," < 15s","nmapmssql",["Failed to resolve"]],

                #68
                ["open",0,proc_low," < 15s","nmapmysql",["Failed to resolve"]],

                #69
                ["open",0,proc_low," < 15s","nmaporacle",["Failed to resolve"]],

                #70
                ["open",0,proc_low," < 15s","nmapudprdp",["Failed to resolve"]],

                #71
                ["open",0,proc_low," < 15s","nmaptcprdp",["Failed to resolve"]],

                #72
                ["open",0,proc_high," > 50m","nmapfulltcp",["Failed to resolve"]],

                #73
                ["open",0,proc_high," > 75m","nmapfulludp",["Failed to resolve"]],

                #74
                ["open",0,proc_low," < 30s","nmapsnmp",["Failed to resolve"]],

                #75
                ["Microsoft SQL Server Error Log",0,proc_low," < 30s","elmahxd",["unable to resolve host address","Connection timed out"]],

                #76
                ["open",0,proc_low," < 20s","nmaptcpsmb",["Failed to resolve"]],

                #77
                ["open",0,proc_low," < 20s","nmapudpsmb",["Failed to resolve"]],

                #78
                ["Host:",0,proc_med," < 5m","wapiti",["none"]],

                #79
                ["WebDAV is ENABLED",0,proc_low," < 40s","nmapwebdaviis",["Failed to resolve"]],

                #80
                ["X-XSS-Protection[1",1,proc_med," < 3m","whatweb",["Timed out","Socket error","X-XSS-Protection[1"]],

                #81
                ["No names were discovered",1,proc_med," < 15m","amass",["The system was unable to build the pool of resolvers"]]
            ]

# Vulnerabilities and Remediation
tools_fix = [
                    [1, "Geen kwetsbaarheid, maar een informatieve waarschuwing. De host heeft geen IPv6-ondersteuning. IPv6 biedt meer veiligheid, omdat IPSec (verantwoordelijk voor CIA - Confidentiality, Integrity and Availablity) in dit model is opgenomen. Het is dus goed om IPv6-ondersteuning te hebben.",
                            "Het wordt aanbevolen om IPv6 te implementeren. Meer informatie over het implementeren van IPv6 vindt u in deze bron. https://www.cisco.com/c/en/us/solutions/collateral/enterprise/cisco-on-cisco/IPv6-Implementation_CS.html"],
                    [2, "Gevoelige informatie Lekkage gedetecteerd. De ASP.Net applicatie filtert geen illegal characters uit de URL. De aanvaller injecteert een speciaal teken (%7C~.aspx) om de applicatie gevoelige informatie over de serverstack te laten verstrekken.",
                            "Het wordt aanbevolen om special characters in de URL uit te filteren en een aangepaste foutpagina in te stellen voor dergelijke situaties in plaats van standaardfoutmeldingen weer te geven. Deze bron helpt u bij het opzetten van een aangepaste foutpagina op een Microsoft .Net-applicatie. https://docs.microsoft.com/en-us/aspnet/web-forms/overview/older-versions-getting-started/deploying-web-site-projects/displaying-a-custom-error-page-cs"],
                    [3, "Het is niet erg om een CMS in WordPress te hebben. Er is een kans dat de versie kwetsbaarheden bevat of dat eventuele scripts van derden die eraan zijn gekoppeld kwetsbaarheden bevatten.",
                            "Het wordt aanbevolen om de versie van WordPress te verbergen. Deze bron bevat meer informatie over hoe u uw WordPress-blog kunt beveiligen. https://codex.wordpress.org/Hardening_WordPress"],
                    [4, "Het is niet erg om een CMS in Drupal te hebben. Er is een kans dat de versie kwetsbaarheden bevat of dat eventuele scripts van derden die eraan zijn gekoppeld kwetsbaarheden bevatten.",
                            "Het wordt aanbevolen om de versie van Drupal te verbergen. Deze bron bevat meer informatie over hoe u uw Drupal Blog kunt beveiligen. https://www.drupal.org/docs/7/site-building-best-practices/ensure-that-your-site-is-secure"],
                    [5, "Het is niet erg om een CMS in Joomla te hebben. Er is een kans dat de versie kwetsbaarheden bevat of dat eventuele scripts van derden die eraan zijn gekoppeld kwetsbaarheden bevatten",
                            "Het wordt aanbevolen om de versie van Joomla te verbergen. Deze bron bevat meer informatie over hoe u uw Joomla Blog kunt beveiligen. https://www.incapsula.com/blog/10-tips-to-improve-your-joomla-website-security.html"],
                    [6, "Soms bevatten robots.txt of sitemap.xml regels die ervoor zorgen dat bepaalde links die niet bedoeld zijn om te worden geopend/geïndexeerd door crawlers en zoekmachines. Zoekmachines kunnen deze links overslaan, maar aanvallers hebben er direct toegang toe.",
                            "Het is een goede gewoonte om geen gevoelige links op te nemen in de robots of sitemapbestanden."],
                    [7, "Zonder een Web Application Firewall kan een aanvaller proberen om verschillende aanvalspatronen handmatig of met behulp van geautomatiseerde scanners te injecteren. Een geautomatiseerde scanner kan hordes aanvalsvectoren en patronen verzenden om een aanval te valideren, er zijn ook kansen voor de applicatie om DoS`ed (Denial of Service) te krijgen",
                            "Web Application Firewalls bieden uitstekende bescherming tegen veelvoorkomende webaanvallen zoals XSS, SQLi, enz. Ze bieden ook een extra verdedigingslinie voor uw beveiligingsinfrastructuur. Deze bron bevat informatie over firewalls voor webapplicatie die geschikt kunnen zijn voor uw toepassing. https://www.gartner.com/reviews/market/web-application-firewall"],
                    [8, "Open poorten geven aanvallers een hint om de services te misbruiken. Aanvallers proberen bannerinformatie op te halen via de poorten en begrijpen welk type service de host gebruikt",
                            "Het wordt aanbevolen om de poorten van ongebruikte services te sluiten en waar nodig een firewall te gebruiken om de poorten te filteren. Deze bron kan meer inzicht geven. https://security.stackexchange.com/a/145781/6137"],
                    [9, "De kans is heel klein om een doelwit te compromitteren met e-mailadressen. Aanvallers gebruiken dit echter als ondersteunende gegevens om informatie over het doelwit te verzamelen. Een aanvaller kan gebruik maken van de gebruikersnaam op het e-mailadres en brute-force aanvallen uitvoeren op niet alleen e-mailservers, maar ook op andere legitieme panelen zoals SSH, CMS, enz. met een wachtwoordlijst, omdat ze een legitieme naam hebben. Dit is echter een shoot in the dark-scenario, de aanvaller kan al dan niet succesvol zijn, afhankelijk van het interesseniveau",
                            "Aangezien de kans op uitbuiting gering is, is er geen noodzaak om actie te ondernemen. Een perfecte oplossing zou zijn om verschillende gebruikersnamen voor verschillende services te kiezen."],
                    [10, "Zone Transfer onthult belangrijke topologische informatie over het doelwit. De aanvaller kan alle records opvragen en heeft min of meer volledige kennis over uw host.",
                            "Een goede gewoonte is om de zone Transfer te beperken door de master te vertellen wat de IP's zijn van de slaves die toegang kunnen krijgen voor de query. Deze SANS-bron biedt meer informatie. https://www.sans.org/reading-room/whitepapers/dns/securing-dns-zone-transfer-868"],
                    [11, "Het e-mailadres van de beheerder en andere informatie (adres, telefoon, enz.) is openbaar beschikbaar. Een aanvaller kan deze informatie gebruiken om een aanval uit te voeren. Dit mag niet worden gebruikt om een directe aanval uit te voeren, aangezien dit geen kwetsbaarheid is. Een aanvaller maakt echter gebruik van deze gegevens om informatie over het doelwit op te bouwen.",
                            "Sommige beheerders zouden deze informatie opzettelijk openbaar hebben gemaakt, in dit geval kan deze worden genegeerd. Zo niet, dan is het aan te raden de informatie te maskeren. Deze bron biedt informatie over deze oplossing. http://www.name.com/blog/how-tos/tutorial-2/2013/06/protect-your-personal-information-with-whois-privacy/"],
                    [12, "Omdat het doelwit deze header mist, zijn oudere browsers vatbaar voor Reflected XSS-aanvallen.",
                            "Moderne browsers hebben geen problemen met deze kwetsbaarheid (missing headers). Oudere browsers worden echter sterk aanbevolen om te worden geüpgraded."],
                    [13, "Deze aanval werkt door meerdere gelijktijdige verbindingen met de webserver te openen en houdt ze zo lang mogelijk in leven door continu gedeeltelijke HTTP-verzoeken te verzenden, die nooit worden voltooid. Ze glippen gemakkelijk door IDS door gedeeltelijke verzoeken te verzenden.",
                            "Als je Apache Module gebruikt, zou `mod_antiloris` helpen. Voor andere instellingen kunt u meer gedetailleerde oplossingen vinden op deze bron. https://www.acunetix.com/blog/articles/slow-http-dos-attacks-mitigate-apache-http-server/"],
                    [14, "Dit beveiligingslek lekt ernstig privégegevens van uw host. Een aanvaller kan de TLS-verbinding in leven houden en kan maximaal 64K aan data per heartbeat ophalen.",
                            "PFS (Perfect Forward Secrecy) kan worden geïmplementeerd om decodering moeilijk te maken. Volledige herstel- en broninformatie is hier beschikbaar. http://heartbleed.com/"],
                    [15, "Door misbruik te maken van dit beveiligingslek, kan een aanvaller toegang krijgen tot gevoelige gegevens in een versleutelde sessie, zoals sessie-ID's, cookies en met de verkregen gegevens kan hij zich voor die specifieke gebruiker voordoen.",
                            "Dit is een fout in het SSL 3.0-protocol. Een betere oplossing zou zijn om het gebruik van het SSL 3.0-protocol uit te schakelen. Raadpleeg deze bron voor meer informatie. https://www.us-cert.gov/ncas/alerts/TA14-290A"],
                    [16, "Deze aanval vindt plaats in de SSL Negotiation (Handshake) waardoor de client niet op de hoogte is van de aanval. Door de handshake met succes te wijzigen, kan de aanvaller alle informatie die van de client naar de server wordt verzonden en vice versa, proberen te achterhalen",
                            "Het upgraden van OpenSSL naar de nieuwste versies verhelpt dit probleem. Deze bron geeft meer informatie over de kwetsbaarheid en het bijbehorende herstel. http://ccsinjection.lepidum.co.jp/"],
                    [17, "Met deze kwetsbaarheid kan de aanvaller een MiTM-aanval uitvoeren en daarmee de vertrouwelijkheidsfactor in gevaar brengen.",
                            "Het upgraden van OpenSSL naar de nieuwste versie verhelpt dit probleem. Versies ouder dan 1.1.0 zijn gevoelig voor dit beveiligingslek. Meer informatie is te vinden in deze bron. https://bobcares.com/blog/how-to-fix-sweet32-birthday-attacks-vulnerability-cve-2016-2183/"],
                    [18, "Met de LogJam-aanval kan de aanvaller de TLS-verbinding downgraden, waardoor de aanvaller alle gegevens die via de verbinding worden doorgegeven, kan lezen en wijzigen.",
                            "Zorg ervoor dat alle TLS-libraries die u gebruikt up-to-date zijn, dat servers die u onderhoudt gebruik maken van 2048-bits of grotere priemgetallen en dat clients die u onderhoudt Diffie-Hellman-primes kleiner dan 1024-bits weigeren. Meer informatie is te vinden in deze bron. https://weakdh.org/"],
                    [19, "Stelt remote attacker in staat een denial of service (crash) te veroorzaken en mogelijk gevoelige informatie te verkrijgen in applicaties die OpenSSL gebruiken, via een misvormd ClientHello-handshakebericht dat een out-of-bounds geheugentoegang activeert.",
                            "OpenSSL-versies 0.9.8h tot 0.9.8q en 1.0.0 tot 1.0.0c zijn kwetsbaar. Het wordt aanbevolen om de OpenSSL-versie te upgraden. Meer bronnen en informatie vindt u hier. https://www.openssl.org/news/secadv/20110208.txt"],
                    [20, "Ook wel BREACH-aanval genoemd, maakt gebruik van de compression in het onderliggende HTTP-protocol. Een aanvaller kan e-mailadressen, sessietokens, enz. verkrijgen van het TLS-gecodeerde webverkeer.",
                            "Het uitschakelen van TLS compression verkleint dit beveiligingslek niet. De eerste stap naar mitigatie is om Zlib compression uit te schakelen, gevolgd door andere maatregelen die in deze bron worden genoemd. http://breachattack.com/"],
                    [21, "Wordt ook wel Plain-Text Injection-aanval genoemd, waarmee MiTM-aanvallers gegevens kunnen invoegen in HTTPS-sessies, en mogelijk andere soorten sessies die worden beschermd door TLS of SSL, door een niet-geverifieerd verzoek te verzenden dat met terugwerkende kracht wordt verwerkt door een server in een context na pot-renegotiation.",
                            "Gedetailleerde herstelstappen zijn te vinden in deze bronnen. https://securingtomorrow.mcafee.com/technical-how-to/tips-securing-ssl-renegotiation/ https://www.digicert.com/news/2011-06-03-ssl-renego/"],
                    [22, "Door dit beveiligingslek kunnen aanvallers bestaande TLS-sessies van gebruikers stelen.",
                            "Beter advies is om het hervatten van sessies uit te schakelen. Volg deze bron met aanzienlijke informatie om de hervatting van de sessie te verharden. https://wiki.crashtest-security.com/display/KB/Harden+TLS+Session+Resumption"],
                    [23, "Dit heeft niets te maken met beveiligingsrisico's, maar aanvallers kunnen deze onbeschikbaarheid van load balancers gebruiken als een voordeel om een denial-of-service-aanval op bepaalde services of op de hele applicatie zelf uit te voeren.",
                            "Load-balancers worden sterk aanbevolen voor webapplicaties. Ze verbeteren de prestatietijden en de beschikbaarheid van gegevens in tijden van serveruitval. Raadpleeg deze bron voor meer informatie over load balancers en instellingen. https://www.digitalocean.com/community/tutorials/what-is-load-balancing"],
                    [24, "Een aanvaller kan verzoeken die naar de legitieme URL of webapplicatie komen, doorsturen naar een adres van een derde partij of naar de locatie van de aanvaller die malware kan leveren en de computer van de eindgebruiker kan beïnvloeden.",
                            "Het wordt ten zeerste aanbevolen om DNSSec op het hostdoel te implementeren. Volledige implementatie van DNSSEC zorgt ervoor dat de eindgebruiker verbinding maakt met de daadwerkelijke website of andere service die overeenkomt met een bepaalde domeinnaam. Raadpleeg deze bron voor meer informatie. https://www.cloudflare.com/dns/dnssec/how-dnssec-works/"],
                    [25, "Aanvallers kunnen een aanzienlijke hoeveelheid informatie uit deze bestanden vinden. Er is zelfs een kans dat aanvallers toegang krijgen tot kritieke informatie uit deze bestanden.",
                            "Het wordt aanbevolen om de toegang tot deze bestanden te blokkeren of te beperken, tenzij dit nodig is."],
                    [26, "Aanvallers kunnen een aanzienlijke hoeveelheid informatie uit deze mappen vinden. Er is zelfs een kans dat aanvallers toegang krijgen tot kritieke informatie uit deze mappen.",
                            "Het wordt aanbevolen om de toegang tot deze mappen te blokkeren of te beperken, tenzij dat nodig is."],
                    [27, "Mag niet SQLi-kwetsbaar zijn. Een aanvaller kan weten dat de host een backend gebruikt voor bewerking.",
                            "Banner Grabbing moet worden beperkt en de toegang tot de diensten van buitenaf moet tot een minimum worden beperkt."],
                    [28, "Een aanvaller kan cookies stelen, webapplicaties onleesbaar maken of omleiden naar elk adres van een derde partij dat malware kan leveren.",
                            "Inputvalidatie en Output Sanitization kunnen Cross Site Scripting (XSS)-aanvallen volledig voorkomen. XSS-aanvallen kunnen in de toekomst worden beperkt door een veilige coderingsmethode op de juiste manier te volgen. De volgende uitgebreide bron biedt gedetailleerde informatie over het oplossen van dit beveiligingslek. https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet"],
                    [29, "SSL-gerelateerde kwetsbaarheden doorbreken de vertrouwelijkheidsfactor. Een aanvaller kan een MiTM-aanval uitvoeren, de communicatie interpreteren en afluisteren.",
                            "Een juiste implementatie en geüpgradede versie van SSL- en TLS libraries zijn erg belangrijk als het gaat om het blokkeren van SSL-gerelateerde kwetsbaarheden."],
                    [30, "Particular Scanner heeft meerdere kwetsbaarheden gevonden die een aanvaller kan proberen het doelwit te misbruiken.",
                            "Raadpleeg RS-Vulnerability-Report om de volledige informatie over de kwetsbaarheid te bekijken, zodra de scan is voltooid."],
                    [31, "Aanvallers kunnen meer informatie verzamelen uit subdomeinen die betrekking hebben op het bovenliggende domein. Aanvallers kunnen zelfs andere services van de subdomeinen vinden en proberen de architectuur van het doelwit te leren. Er zijn zelfs kansen voor de aanvaller om kwetsbaarheden te vinden naarmate het aanvalsoppervlak groter wordt naarmate er meer subdomeinen worden ontdekt.",
                            "Soms is het verstandig om subdomeinen zoals development, staging naar de buitenwereld te blokkeren, omdat dit de aanvaller meer informatie geeft over de tech stack. Complexe naamgevingspraktijken helpen ook bij het verkleinen van het aanvalsoppervlak, aangezien aanvallers moeite hebben om subdomein bruteforcing uit te voeren via dictionaries en wordlists."],
                    [32, "Via dit verouderde protocol kan een aanvaller mogelijk MiTM en andere gecompliceerde aanvallen uitvoeren.",
                            "Het wordt ten zeerste aanbevolen om te stoppen met het gebruik van deze service en deze is ver achterhaald. SSH kan worden gebruikt om TELNET te vervangen. Raadpleeg deze bron voor meer informatie https://www.ssh.com/ssh/telnet"],
                    [33, "Dit protocol ondersteunt geen beveiligde communicatie en de kans is groot dat de aanvaller de communicatie afluistert. Ook hebben veel FTP-programma's exploits beschikbaar op het web, zodat een aanvaller de applicatie direct kan laten crashen of ofwel een SHELL-toegang tot dat doel kan krijgen.",
                            "De juiste voorgestelde oplossing is het gebruik van een SSH-protocol in plaats van FTP. Het ondersteunt veilige communicatie en de kans op MiTM-aanvallen is vrij zeldzaam."],
                    [34, "Het StuxNet is een worm van niveau 3 die kritieke informatie van de doelorganisatie blootlegt. Het was een cyberwapen dat was ontworpen om de nucleaire inlichtingendienst van Iran te dwarsbomen. Vraag je je serieus af hoe het hier is gekomen? Ik hoop dat dit geen vals-positieve Nmap is;)",
                            "Het wordt ten zeerste aanbevolen om een volledige rootkit-scan op de host uit te voeren. Raadpleeg deze bron voor meer informatie. https://www.symantec.com/security_response/writeup.jsp?docid=2010-071400-3123-99&tabid=3"],
                    [35, "WebDAV zou meerdere kwetsbaarheden moeten bevatten. In sommige gevallen kan een aanvaller echter een kwaadaardig DLL-bestand in de WebDAV-share verbergen en de gebruiker overtuigen om een volkomen onschadelijk en legitiem bestand te openen, code uitvoeren in de context van die gebruiker",
                            "Het wordt aanbevolen om WebDAV uit te schakelen. Een kritische bron met betrekking tot het uitschakelen van WebDAV is te vinden op deze URL. https://www.networkworld.com/article/2202909/network-security/-webdav-is-bad---says-security-researcher.html"],
                    [36, "Aanvallers maken altijd een fingerprint van een server voordat ze een aanval lanceren. Fingerprints geven ze informatie over het servertype, de inhoud die ze serveren, de laatste wijzigingstijden enz. Dit geeft een aanvaller meer informatie over het doelwit",
                            "Een goede gewoonte is om de informatie voor de buitenwereld te verdoezelen. Door dit te doen, zullen de aanvallers moeite hebben om de technische stack van de server te begrijpen en daarom een aanval gebruiken."],
                    [37, "Aanvallers proberen meestal webapplicaties of -service onbruikbaar te maken door het doelwit te overspoelen, zodat de toegang voor legitieme gebruikers wordt geblokkeerd. Dit kan van invloed zijn op de bedrijfsvoering van een bedrijf of organisatie, evenals op de reputatie",
                            "Door ervoor te zorgen dat de juiste load balancers aanwezig zijn, snelheidslimieten en meerdere verbindingsbeperkingen te configureren, kunnen dergelijke aanvallen drastisch worden beperkt."],
                    [38, "Indringers kunnen op afstand shell-files toevoegen en hebben toegang tot het kernbestandssysteem of ze kunnen ook alle bestanden lezen. Er zijn zelfs nog grotere kansen voor de aanvaller om op afstand code uit te voeren op het bestandssysteem.",
                            "Veilige codepraktijken zullen vooral LFI-, RFI- en RCE-aanvallen voorkomen. De volgende bron geeft een gedetailleerd inzicht in veilige coderingspraktijken. https://wiki.sei.cmu.edu/confluence/display/seccode/Top+10+Secure+Coding+Practices"],
                    [39, "Hackers kunnen gegevens van de backend stelen en ze kunnen zichzelf ook authenticeren op de website en kunnen zich voordoen als elke gebruiker, aangezien ze volledige controle hebben over de backend. Ze kunnen zelfs de hele database wissen. Aanvallers kunnen ook cookie-informatie van een geverifieerde gebruiker stelen en ze kunnen het doelwit zelfs omleiden naar een kwaadaardig adres of de applicatie volledig onleesbaar maken.",
                            "De juiste invoervalidatie moet worden uitgevoerd voordat de database-informatie rechtstreeks wordt opgevraagd. Een ontwikkelaar moet onthouden dat hij de input van een eindgebruiker niet mag vertrouwen. Door een veilige coderingsmethode te volgen, vallen aanvallen zoals SQLi, XSS en BSQLi. De volgende hulpbrongidsen over het implementeren van veilige coderingsmethodologie bij applicatie ontwikkeling. https://wiki.sei.cmu.edu/confluence/display/seccode/Top+10+Secure+Coding+Practices"],
                    [40, "Aanvallers misbruiken het beveiligingslek in BASH om externe code op het doelwit uit te voeren. Een ervaren aanvaller kan gemakkelijk het doelsysteem overnemen en toegang krijgen tot de interne bronnen van de machine",
                            "Dit beveiligingslek kan worden verholpen door de versie van BASH te patchen. De volgende bron geeft een diepgaande analyse van de kwetsbaarheid en hoe deze te verminderen. https://www.symantec.com/connect/blogs/shellshock-all-you-need-know-about-bash-bug-vulnerability https://www.digitalocean.com/community/tutorials/how-to-protect-your-server-against-the-shellshock-bash-vulnerability"],
                    [41, "Geeft de aanvaller een idee over hoe de adresschets intern op het organisatienetwerk wordt uitgevoerd. Het ontdekken van de privéadressen die binnen een organisatie worden gebruikt, kan aanvallers helpen bij het uitvoeren van netwerklaagaanvallen die erop gericht zijn de interne infrastructuur van de organisatie binnen te dringen.",
                            "Beperk de bannerinformatie tot de buitenwereld van de openbaarmakingsservice. Meer informatie over het verminderen van dit beveiligingslek vindt u hier. https://portswigger.net/kb/issues/00600300_private-ip-addresses-disclosed"],
                    [42, "Er zijn kansen voor een aanvaller om bestanden op de webserver te manipuleren.",
                            "Het wordt aanbevolen om de HTTP PUT- en DEL-methoden uit te schakelen als u geen REST API-services gebruikt. De volgende bronnen helpen u deze methoden uit te schakelen.http://www.techstacks.com/howto/disable-http-methods-in-tomcat.html https://docs.oracle.com/cd/E19857-01/820-5627/gghwc/index.html https://developer.ibm.com/answers/questions/321629/how-to-disable-http-methods-head-put-delete-option/"],
                    [43, "Aanvallers proberen meer over het doelwit te weten te komen uit de hoeveelheid informatie die in de headers wordt weergegeven. Een aanvaller weet mogelijk welk type tech stack een webapplicatie benadrukt en vele andere informatie.",
                            "Banner Grabbing moet worden beperkt en de toegang tot de diensten van buitenaf moet tot een minimum worden beperkt."],
                    [44, "Een aanvaller die misbruik weet te maken van dit beveiligingslek, kan gegevens lezen, zoals de weergavestatus, die door de server zijn versleuteld. Dit beveiligingslek kan ook worden gebruikt voor gegevensmanipulatie, die, indien succesvol misbruikt, kan worden gebruikt om de gegevens die door de server zijn versleuteld te ontsleutelen en ermee te knoeien.",
                            "Microsoft heeft een reeks patches op hun website uitgebracht om dit probleem te verhelpen. De informatie die nodig is om dit beveiligingslek te verhelpen, kan worden afgeleid uit deze bron. https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-070"],
                    [45, "Elke verouderde webserver kan meerdere kwetsbaarheden bevatten, omdat hun ondersteuning zou zijn beëindigd. Een aanvaller kan van een dergelijke mogelijkheid gebruikmaken om aanvallen uit te voeren.",
                            "Het wordt ten zeerste aanbevolen om de webserver te upgraden naar de beschikbare nieuwste versie."],
                    [46, "Hackers kunnen de URL's gemakkelijk manipuleren via een GET/POST request. Ze kunnen gemakkelijk meerdere aanvalsvectoren in de URL injecteren en ook de reactie monitoren",
                            "Door te zorgen voor de juiste ontsmettingstechnieken en veilige coderingspraktijken te gebruiken, zal het voor de aanvaller onmogelijk zijn om door te dringen. De volgende bron geeft een gedetailleerd inzicht in veilige coderingspraktijken. https://wiki.sei.cmu.edu/confluence/display/seccode/Top+10+Secure+Coding+Practices"],
                    [47, "Aangezien de aanvaller kennis heeft van het specifieke type backend dat het doelwit gebruikt, kan hij een gerichte exploit voor de specifieke versie lanceren. Ze kunnen ook proberen zich te authenticeren met standaardreferenties om zichzelf erdoorheen te krijgen.",
                            "Tijdige beveiligingspatches voor de backend moeten worden geïnstalleerd. Standaardreferenties moeten worden gewijzigd. Indien mogelijk kan de bannerinformatie worden gewijzigd om de aanvaller te misleiden. De volgende bron geeft meer informatie over hoe u uw backend kunt beveiligen. http://kb.bodhost.com/secure-database-server/"],
                    [48, "Aanvallers kunnen externe exploits lanceren om de service te laten crashen of tools zoals ncrack om het wachtwoord op het doelwit te brute-forcen.",
                            "Het wordt aanbevolen om de service voor de buitenwereld te blokkeren en de service alleen toegankelijk te maken via een reeks toegestane IP's die alleen echt nodig zijn. De volgende bron biedt inzicht in de risico's en de stappen om de service te blokkeren. https://www.perspectiverisk.com/remote-desktop-service-vulnerabilities/"],
                    [49, "Hackers kunnen community-strings via de service lezen en behoorlijk wat informatie van het doelwit opsommen. Er zijn ook meerdere kwetsbaarheden voor het uitvoeren van externe code en denial of service gerelateerd aan SNMP-services.",
                            "Gebruik een firewall om de poorten van de buitenwereld te blokkeren. Het volgende artikel geeft een breed inzicht in het vergrendelen van de SNMP-service. https://www.techrepublic.com/article/lock-it-down-dont-allow-snmp-to-compromise-network-security/"],
                    [50, "Aanvallers kunnen de logbestanden en error informatie vinden die door de applicatie zijn gegenereerd. Ze kunnen ook de statuscodes zien die in de applicatie zijn gegenereerd. Door al deze informatie te combineren, kan de aanvaller een aanval gebruiken.",
                            "Door de toegang tot de loggerapplicatie van de buitenwereld te beperken, zal meer dan voldoende zijn om deze zwakte te verminderen."],
                    [51, "Cybercriminelen richten zich voornamelijk op deze service, omdat het voor hen veel gemakkelijker is om een aanval op afstand uit te voeren door exploits uit te voeren. WannaCry Ransomware is zo'n voorbeeld.",
                            "SMB Service aan de buitenwereld blootstellen is een slecht idee, het wordt aanbevolen om de nieuwste patches voor de service te installeren om niet gecompromitteerd te raken. De volgende bron biedt gedetailleerde informatie over SMB-verhardingsconcepten. https://kb.iweb.com/hc/en-us/articles/115000274491-Securing-Windows-SMB-and-NetBios-NetBT-Services"]
            ]

# Tool Set
tools_precheck = [
                    ["wapiti"], ["whatweb"], ["nmap"], ["golismero"], ["host"], ["wget"], ["uniscan"], ["wafw00f"], ["dirb"], ["davtest"], ["theHarvester"], ["xsser"], ["dnsrecon"],["fierce"], ["dnswalk"], ["whois"], ["sslyze"], ["lbd"], ["golismero"], ["dnsenum"],["dmitry"], ["davtest"], ["nikto"], ["dnsmap"], ["amass"]
                 ]

def get_parser():

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-h', '--help', action='store_true', 
                        help='Show help message and exit.')
    #parser.add_argument('-u', '--update', action='store_true', 
    #                    help='Update RapidScan.')
    parser.add_argument('-s', '--skip', action='append', default=[],
                        help='Skip some tools', choices=[t[0] for t in tools_precheck])
    parser.add_argument('-n', '--nospinner', action='store_true', 
                        help='Disable the idle loader/spinner.')
    parser.add_argument('target', nargs='?', metavar='URL', help='URL to scan.', default='', type=str)
    return parser


# Shuffling Scan Order (starts)
scan_shuffle = list(zip(tool_names, tool_cmd, tool_resp, tool_status))
random.shuffle(scan_shuffle)
tool_names, tool_cmd, tool_resp, tool_status = zip(*scan_shuffle)
tool_checks = (len(tool_names) + len(tool_resp) + len(tool_status)) / 3 # Cross verification incase, breaks.
tool_checks = round(tool_checks)
# Shuffling Scan Order (ends)

# Tool Head Pointer: (can be increased but certain tools will be skipped)
tool = 0

# Run Test
runTest = 1

# For accessing list/dictionary elements
arg1 = 0
arg2 = 1
arg3 = 2
arg4 = 3
arg5 = 4
arg6 = 5

# Detected Vulnerabilities [will be dynamically populated]
rs_vul_list = list()
rs_vul_num = 0
rs_vul = 0

# Total Time Elapsed
rs_total_elapsed = 0

# Tool Pre Checker
rs_avail_tools = 0

# Checks Skipped
rs_skipped_checks = 0

if len(sys.argv) == 1:
    logo()
    helper()
    sys.exit(1)

args_namespace = get_parser().parse_args()

if args_namespace.nospinner:
    spinner.disabled = True

if args_namespace.help or (not args_namespace.update \
    and not args_namespace.target):
    logo()
    helper()

elif args_namespace.target:

    target = url_maker(args_namespace.target)
    #target = args_namespace.target
    os.system('rm /tmp/te* > /dev/null 2>&1') # Clearing previous scan files
    os.system('clear')
    os.system('setterm -cursor off')
    logo()
    print(bcolors.BG_HEAD_TXT+"[ Beschikbare tools voor beveiligingsscans controleren Fase... Gestart. ]"+bcolors.ENDC)

    unavail_tools_names = list()

    while (rs_avail_tools < len(tools_precheck)):
        precmd = str(tools_precheck[rs_avail_tools][arg1])
        try:
            p = subprocess.Popen([precmd], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,shell=True)
            output, err = p.communicate()
            val = output + err
        except:
            print("\t"+bcolors.BG_ERR_TXT+"DNS-Scan werd abrupt beëindigd..."+bcolors.ENDC)
            sys.exit(1)
        
        # If the tool is not found or it's part of the --skip argument(s), disabling it
        if b"Niet gevonden" in val or tools_precheck[rs_avail_tools][arg1] in args_namespace.skip :
            if b"Niet gevonden" in val:
                print("\t"+bcolors.OKBLUE+tools_precheck[rs_avail_tools][arg1]+bcolors.ENDC+bcolors.BADFAIL+"...Niet beschikbaar."+bcolors.ENDC)
            elif tools_precheck[rs_avail_tools][arg1] in args_namespace.skip :
                print("\t"+bcolors.OKBLUE+tools_precheck[rs_avail_tools][arg1]+bcolors.ENDC+bcolors.BADFAIL+"...Overgeslagen."+bcolors.ENDC)
            
            for scanner_index, scanner_val in enumerate(tool_names):
                if scanner_val[2] == tools_precheck[rs_avail_tools][arg1]:
                    scanner_val[3] = 0 # disabling scanner as it's not available.
                    unavail_tools_names.append(tools_precheck[rs_avail_tools][arg1])

        else:
            print("\t"+bcolors.OKBLUE+tools_precheck[rs_avail_tools][arg1]+bcolors.ENDC+bcolors.OKGREEN+"...beschikbaar."+bcolors.ENDC)
        rs_avail_tools = rs_avail_tools + 1
        clear()
    unavail_tools_names = list(set(unavail_tools_names))
    if len(unavail_tools_names) == 0:
        print("\t"+bcolors.OKGREEN+"Alle scantools zijn beschikbaar. Volledige kwetsbaarheidscontroles worden uitgevoerd door RapidScan."+bcolors.ENDC)
    else:
        print("\t"+bcolors.WARNING+"Sommige van deze tools "+bcolors.BADFAIL+str(unavail_tools_names)+bcolors.ENDC+bcolors.WARNING+" zijn niet beschikbaar of worden overgeslagen. DNS-Scan zal de rest van de tests nog steeds uitvoeren. Installeer deze tools om de functionaliteit van DNS-Scan volledig te benutten."+bcolors.ENDC)
    print(bcolors.BG_ENDL_TXT+"[ Beschikbare tools voor beveiligingsscannen controleren Fase... Voltooid. ]"+bcolors.ENDC)
    print("\n")
    print(bcolors.BG_HEAD_TXT+"[ Voorlopige scanfase gestart... Loaded "+str(tool_checks)+" kwetsbaarheidscontroles. ]"+bcolors.ENDC)
    #while (tool < 1):
    while(tool < len(tool_names)):
        print("["+tool_status[tool][arg3]+tool_status[tool][arg4]+"] Inzetten "+str(tool+1)+"/"+str(tool_checks)+" | "+bcolors.OKBLUE+tool_names[tool][arg2]+bcolors.ENDC,)
        if tool_names[tool][arg4] == 0:
            print(bcolors.WARNING+"\nScantool niet beschikbaar. Test overslaan...\n"+bcolors.ENDC)
            rs_skipped_checks = rs_skipped_checks + 1
            tool = tool + 1
            continue
        try:
            spinner.start()
        except Exception as e:
            print("\n")
        scan_start = time.time()
        temp_file = "/tmp/dns-scan_temp_"+tool_names[tool][arg1]
        cmd = tool_cmd[tool][arg1]+target+tool_cmd[tool][arg2]+" > "+temp_file+" 2>&1"

        try:
            subprocess.check_output(cmd, shell=True)
        except KeyboardInterrupt:
            runTest = 0
        except:
            runTest = 1

        if runTest == 1:
                spinner.stop()
                scan_stop = time.time()
                elapsed = scan_stop - scan_start
                rs_total_elapsed = rs_total_elapsed + elapsed
                #print(bcolors.OKBLUE+"\b...Completed in "+display_time(int(elapsed))+bcolors.ENDC+"\n")
                sys.stdout.write(ERASE_LINE)
                print(bcolors.OKBLUE+"\nScan voltooid in "+display_time(int(elapsed))+bcolors.ENDC, end='\r', flush=True)
                print("\n")
                #clear()
                rs_tool_output_file = open(temp_file).read()
                if tool_status[tool][arg2] == 0:
                    if tool_status[tool][arg1].lower() in rs_tool_output_file.lower():
                        #print "\t"+ vul_info(tool_resp[tool][arg2]) + bcolors.BADFAIL +" "+ tool_resp[tool][arg1] + bcolors.ENDC
                        vul_remed_info(tool,tool_resp[tool][arg2],tool_resp[tool][arg3])
                        rs_vul_list.append(tool_names[tool][arg1]+"*"+tool_names[tool][arg2])
                else:
                    if any(i in rs_tool_output_file for i in tool_status[tool][arg6]):
                        m = 1 # This does nothing.
                    else:
                        #print "\t"+ vul_info(tool_resp[tool][arg2]) + bcolors.BADFAIL +" "+ tool_resp[tool][arg1] + bcolors.ENDC
                        vul_remed_info(tool,tool_resp[tool][arg2],tool_resp[tool][arg3])
                        rs_vul_list.append(tool_names[tool][arg1]+"*"+tool_names[tool][arg2])
        else:
                runTest = 1
                spinner.stop()
                scan_stop = time.time()
                elapsed = scan_stop - scan_start
                rs_total_elapsed = rs_total_elapsed + elapsed
                sys.stdout.write(ERASE_LINE)
                print(bcolors.OKBLUE+"\nScan onderbroken in "+display_time(int(elapsed))+bcolors.ENDC, end='\r', flush=True)
                print("\n"+bcolors.WARNING + "\tTest overgeslagen. Volgende uitvoeren. Druk op Ctrl+Z om dns-scan af te sluiten.\n" + bcolors.ENDC)
                rs_skipped_checks = rs_skipped_checks + 1

        tool=tool+1

    print(bcolors.BG_ENDL_TXT+"[ Voorlopige scanfase voltooid. ]"+bcolors.ENDC)
    print("\n")

    #################### Report & Documentation Phase ###########################
    print(bcolors.BG_HEAD_TXT+"[ Rapportgeneratiefase gestart. ]"+bcolors.ENDC)
    if len(rs_vul_list)==0:
        print("\t"+bcolors.OKGREEN+"Geen kwetsbaarheid gedecteerd."+bcolors.ENDC)
    else:
        with open("RS-Vulnerability-Report", "a") as report:
            while(rs_vul < len(rs_vul_list)):
                vuln_info = rs_vul_list[rs_vul].split('*')
                report.write(vuln_info[arg2])
                report.write("\n------------------------\n\n")
                temp_report_name = "/tmp/dns-scan_temp_"+vuln_info[arg1]
                with open(temp_report_name, 'r') as temp_report:
                    data = temp_report.read()
                    report.write(data)
                    report.write("\n\n")
                temp_report.close()
                rs_vul = rs_vul + 1

            print("\tCompleet kwetsbaarheidsrapport voor "+bcolors.OKBLUE+target+bcolors.ENDC+" genaamd "+bcolors.OKGREEN+"`RS-Vulnerability-Report`"+bcolors.ENDC+" is beschikbaar onder dezelfde directory waar dns-scan zich bevindt.")

        report.close()
    # Writing all scan files output into RS-Debug-ScanLog for debugging purposes.
    for file_index, file_name in enumerate(tool_names):
        with open("RS-Debug-ScanLog", "a") as report:
            try:
                with open("/tmp/rapidscan_temp_"+file_name[arg1], 'r') as temp_report:
                        data = temp_report.read()
                        report.write(file_name[arg2])
                        report.write("\n------------------------\n\n")
                        report.write(data)
                        report.write("\n\n")
                temp_report.close()
            except:
                break
        report.close()

    print("\tTotaal aantal kwetsbaarheidscontroles       : "+bcolors.BOLD+bcolors.OKGREEN+str(len(tool_names))+bcolors.ENDC)
    print("\tTotal Number of Vulnerability Checks Skipped: "+bcolors.BOLD+bcolors.WARNING+str(rs_skipped_checks)+bcolors.ENDC)
    print("\tTotaal aantal gedetecteerde kwetsbaarheden  : "+bcolors.BOLD+bcolors.BADFAIL+str(len(rs_vul_list))+bcolors.ENDC)
    print("\tTotale verstreken tijd voor de scan         : "+bcolors.BOLD+bcolors.OKBLUE+display_time(int(rs_total_elapsed))+bcolors.ENDC)
    print("\n")
    print("\tVoor debugging doeleinden kunt u de volledige uitvoer bekijken die is gegenereerd door alle tools met de naam"+bcolors.OKBLUE+"`RS-Debug-ScanLog`"+bcolors.ENDC+" onder dezelfde map.")
    print(bcolors.BG_ENDL_TXT+"[ Rapportgeneratiefase voltooid. ]"+bcolors.ENDC)

    os.system('setterm -cursor on')
    os.system('rm /tmp/dns-scan_te* > /dev/null 2>&1') # Clearing previous scan files
