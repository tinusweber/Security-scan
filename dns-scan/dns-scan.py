import os
import sys
import atexit
import importlib.util

import json
import socket
import requests
import datetime
import ipaddress
import tldextract
import argparse

R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyans  
W = '\033[0m'  # white

version = '1.0.2'
home = os.getenv('HOME')
pid_path = home + '/.local/share/dns-scan/dns-scan.pid'
usr_data = home + '/.local/share/dns-scan/dumps/'
conf_path = home + '/.config/dns-scan'
path_to_script = os.path.dirname(os.path.realpath(__file__))
src_conf_path = path_to_script + '/conf/'
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
with open(path_to_script + '/requirements.txt', 'r') as rqr:
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

#Argument usage.
parser = argparse.ArgumentParser()
parser.add_argument('url', help='Target URL')

#Argument scans.
parser.add_argument('--headers', help='Header Information', action='store_true')
parser.add_argument('--whois', help='Whois Lookup', action='store_true')

#Argument voor extra opties.
ext_help = parser.add_argument_group('Extra Options')
ext_help.add_argument('-o', help='Export Output [ Default : txt ] [ Available : xml, csv ]')

#Parse arguments.
try:
	args = parser.parse_args()
except SystemExit:
	os.remove(pid_path)
	sys.exit()

type_ip = False
data = {}
meta = {}

target = args.url

headinfo = args.headers
whois = args.whois

output = args.o

#Define full reconnaissance.
def full_recon():
	from modules.headers import headers
	from scans.whois import whois_lookup
	headers(target, output, data)
	whois_lookup(ip, output, data)
    
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
        
    try:
        ipaddress.ip_address(hostname)
        type_ip = True
        ip = hostname
    
    #Check of IP geldig adress is.
    except:
        try:
            ip = socket.gethostbyname(hostname)
            print ('\n' + G + '[+]' + C + ' IP Address : ' + W + str(ip))
        except Exception as e:
            print ('\n' + R + '[-]' + C + ' Unable to Get IP : ' + W + str(e))
            os.remove(pid_path)
            sys.exit()
                
    start_time = datetime.datetime.now()
    meta.update({'Version': str(version)})
    meta.update({'Date': str(datetime.date.today())})
    meta.update({'Target': str(target)})
    meta.update({'IP Address': str(ip)})
    meta.update({'Start Time': str(start_time.strftime('%I:%M:%S %p'))})
    data['module-FinalRecon'] = meta

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
            
    from modules.export import export
    
    if headinfo == True:
        from modules.headers import headers
        headers(target, output, data)
        
    if whois == True:
        from scans.whois import whois_lookup
        whois_lookup(ip, output, data)
    else:
        pass
    
    if any([headinfo, whois]) != True:
        print ('\n' + R + '[-] Error : ' + C + 'At least One Argument is Required with URL' + W)
        output = 'None'
        os.remove(pid_path)
        sys.exit()
        
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