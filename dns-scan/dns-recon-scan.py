from inspect import trace
import os
import sys
import atexit
import importlib.util

R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyans  
W = '\033[0m'  # white

version = '1.0.2'
home = os.getenv('HOME')
#pid_path = home + '/.local/share/dns-scan/dns-scan.pid'
#usr_data = home + '/.local/share/dns-scan/dumps/'
#conf_path = home + '/.config/dns-scan'
pid_path = home + '/Tools/Security-scan/dns-scan/output/dns-scan.pid'
usr_data = home + '/Tools/Security-scan/dns-scan/output/dumps/'
conf_path = home + '/Tools/Security-scan/dns-scan/output/conf/'

path_to_script = os.path.dirname(os.path.realpath(__file__))
src_conf_path = path_to_script + 'output/conf/'
fail = False

#Definieer logo/banner
def logo():
	logo = r'''

 ___ _____    _____   _    _  _______ _   _ 
|_ _|_   _|  |__  /  / \  | |/ / ____| \ | |
 | |  | |_____ / /  / _ \ | ' /|  _| |  \| |
 | |  | |_____/ /_ / ___ \| . \| |___| |\  |
|___| |_|    /____/_/   \_\_|\_\_____|_| \_|

'''

	print(G + logo + W + '\n')
	print(G + '[>]' + C + ' Created By : ' + W + 'IT-Zaken')
	print(G + '[>]' + C + ' Version    : ' + W + version + '\n')


#Check if scan is already running.
if os.path.isfile(pid_path):
    print(R + '[-]' + C + ' One instance of Domain scan is already running!' + W)
    with open(pid_path, 'r') as pidfile:
        pid = pidfile.read()
        print(G + '[+]' + C + ' PID : ' + W + str(pid))
        print(G + '[>]' + C + ' If Domain scan crashed, execute : ' + W + 'rm {}'.format(pid_path))
        sys.exit()
else:
	os.makedirs(os.path.dirname(pid_path), exist_ok=True)
	with open(pid_path, 'w') as pidfile:
		pidfile.write(str(os.getpid()))

#Check if configuration path already exists.
if os.path.exists(conf_path):
	pass
else:
	import shutil
	shutil.copytree(src_conf_path, conf_path, dirs_exist_ok=True)

#Check if dependencies are installed.
with open(path_to_script + '/install/requirements.txt', 'r') as rqr:
	pkg_list = rqr.read().strip().split('\n')
logo()
print('\n' + G + '[+]' + C + ' Checking Dependencies...' + W + '\n')
for pkg in pkg_list:
	spec = importlib.util.find_spec(pkg)
	if spec is None:
		print(R + '[-]' + W + ' {}'.format(pkg) + C + ' is not Installed!' + W)
		fail = True
	else:
		pass
if fail == True:
	print('\n' + R + '[-]' + C + ' Please Execute ' + W + 'pip3 install -r requirements.txt' + C + ' to Install Missing Packages' + W + '\n')
	os.remove(pid_path)
	sys.exit()

import argparse

#Argument usage.
parser = argparse.ArgumentParser(description='Domain scan | v{}'.format(version))
parser.add_argument('url', help='Target URL')

#Argument scans.
parser.add_argument('--headers', help='Header Information', action='store_true')
parser.add_argument('--whois', help='Whois Lookup', action='store_true')
parser.add_argument('--ps', help='Fast Port Scan', action='store_true')
parser.add_argument('--full', help='Full Recon', action='store_true')
parser.add_argument('--sslinfo', help='SSL Certificate Information', action='store_true')
parser.add_argument('--sub', help='Sub-Domain Enumeration', action='store_true')

#Argument voor extra opties.
ext_help = parser.add_argument_group('Extra Options')
ext_help.add_argument('-o', help='Export Output [ Default : txt ] [ Available : xml, csv ]')
ext_help.add_argument('-e', help='File Extensions [ Example : txt, xml, php ]')

ext_help.add_argument('-p', type=int, help='Port for Traceroute [ Default : 80 / 33434 ]')
ext_help.add_argument('-t', type=int, help='Number of Threads [ Default : 30 ]')
ext_help.add_argument('-T', type=float, help='Request Timeout [ Default : 30.0 ]')
ext_help.add_argument('-w', help='Path to Wordlist [ Default : wordlists/dirb_common.txt ]')
ext_help.add_argument('-r', action='store_true', help='Allow Redirect [ Default : False ]')
ext_help.add_argument('-s', action='store_false', help='Toggle SSL Verification [ Default : True ]')
ext_help.add_argument('-sp', type=int, help='Specify SSL Port [ Default : 443 ]')
ext_help.add_argument('-d', help='Custom DNS Servers [ Default : 1.1.1.1 ]')
ext_help.add_argument('-m', help='Traceroute Mode [ Default : UDP ] [ Available : TCP, ICMP ]')
ext_help.add_argument('-tt', type=float, help='Traceroute Timeout [ Default : 1.0 ]')
ext_help.set_defaults(
	t = 30,
	T = 30.0,
	w = path_to_script + '/wordlists/dirb_common.txt',
	r = False,
	s = True,
	sp = 443,
	d = '1.1.1.1',
	e = '',
	m = 'UDP',
	p = 33434,
	tt = 1.0,
	o = 'txt')

#Parse arguments.
try:
	args = parser.parse_args()
except SystemExit:
	os.remove(pid_path)
	sys.exit()

target = args.url
full = args.full
headinfo = args.headers
whois = args.whois
pscan = args.ps
port = args.p
sslinfo = args.sslinfo
sslp = args.sp
tout = args.T
filext = args.e
subd = args.sub
mode = args.m
tr_tout = args.tt

output = args.o

import json
import socket
import requests
import datetime
import ipaddress
import tldextract

type_ip = False
data = {}
meta = {}

#Define full reconnaissance.
def full_recon():
    from scans.modules.headers import headers
    from scans.sslinfo import cert
    from scans.whois import whois_lookup
    from scans.portscan import ps  
    from scans.subdom import subdomains
    headers(target, output, data)
    cert(hostname, sslp, output, data)
    whois_lookup(ip, output, data)
    if type_ip == False:
        subdomains(domain, tout, output, data, conf_path)
    else:
        pass
    ps(ip, output, data)
       
try:
    logo()

    #Check of domein met http(s):// begint.
    if target.startswith(('http', 'https')) == False:
        print(R + '[-]' + C + ' Protocol Missing, Include ' + W + 'http://' + C + ' or ' + W + 'https://' + '\n')
        os.remove(pid_path)
        sys.exit()
    else:
        pass

    #Check of domein eindigt met /.
    if target.endswith('/') == True:
        target = target[:-1]
    else:
        pass
        
    print (G + '[+]' + C + ' Target : ' + W + target)
    ext = tldextract.extract(target)
    domain = ext.registered_domain
    hostname = '.'.join(part for part in ext if part)

    #Check of IP geldig adress is.    
    try:
        ipaddress.ip_address(hostname)
        type_ip = True
        ip = hostname
    except:
        try:
            ip = socket.gethostbyname(hostname)
            print ('\n' + G + '[+]' + C + ' IP Address : ' + W + str(ip))
        except Exception as e:
            print ('\n' + R + '[-]' + C + ' Unable to Get IP : ' + W + str(e))
            os.remove(pid_path)
            sys.exit()

    #Set scan data.                
    start_time = datetime.datetime.now()

    meta.update({'Version': str(version)})
    meta.update({'Date': str(datetime.date.today())})
    meta.update({'Target': str(target)})
    meta.update({'IP Address': str(ip)})
    meta.update({'Start Time': str(start_time.strftime('%I:%M:%S %p'))})
    data['module-dns_scan'] = meta

    #Check output
    if output != 'None':
        fpath = usr_data
        fname = str(fpath) + str(hostname) + '.' + str(output)
        
        if not os.path.exists(fpath):
                os.makedirs(fpath)
        output = {
		    'format': output,
		    'file': fname,
		    'export': False
		    }
            
    from scans.modules.export import export
    #Full scan
    if full == True:
        full_recon()

    #Header Information.
    if headinfo == True:
        from scans.modules.headers import headers
        headers(target, output, data)

    #WhoIs scan.    
    if whois == True:
        from scans.whois import whois_lookup
        whois_lookup(ip, output, data)
    else:
        pass

    #Port scan.
    if pscan == True:
        from scans.portscan import ps
        ps(ip, output, data)

    #Scan SSL information
    if sslinfo == True:
        from scans.sslinfo import cert
        cert(hostname, sslp, output, data)

    #Scan Sub Domains
    if subd == True and type_ip == False:
        from scans.subdom import subdomains
        subdomains(domain, tout, output, data, conf_path)
    elif subd == True and type_ip == True:
        print(R + '[-]' + C + ' Sub-Domain Enumeration is Not Supported for IP Addresses' + W + '\n')
        os.remove(pid_path)
        sys.exit()
    else:
        pass

    if any([full, headinfo, whois, pscan, sslinfo, subd]) != True: 
        print ('\n' + R + '[-] Error : ' + C + 'At least One Argument is Required with URL' + W)
        output = 'None'
        os.remove(pid_path)
        sys.exit()

    #Set time scan process.    
    end_time = datetime.datetime.now() - start_time
    print ('\n' + G + '[+]' + C + ' Completed in ' + W + str(end_time) + '\n')
    
    @atexit.register
    def call_export():
        meta.update({'End Time': str(datetime.datetime.now().strftime('%I:%M:%S %p'))})
        meta.update({'Completion Time': str(end_time)})
        if output != 'None':
            output['export'] = True
            export(output, data)
            
    os.remove(pid_path)
    sys.exit() 
except KeyboardInterrupt:
    print (R + '[-]' + C + ' Keyboard Interrupt.' + W + '\n')
    os.remove(pid_path)
    sys.exit()