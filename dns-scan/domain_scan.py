import os
import sys
import atexit
import importlib.util

R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyans  
W = '\033[0m'  # white

home = os.getenv('HOME')
pid_path = home + '/.local/share/dns-scan/dns-scan.pid'
usr_data = home + '/.local/share/dns-scan/dumps/'
conf_path = home + '/.config/dns-scan'
path_to_script = os.path.dirname(os.path.realpath(__file__))
src_conf_path = path_to_script + '/conf/'
fail = False

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

if os.path.exists(conf_path):
	pass
else:
	import shutil
	shutil.copytree(src_conf_path, conf_path, dirs_exist_ok=True)

with open(path_to_script + '/requirements.txt', 'r') as rqr:
	pkg_list = rqr.read().strip().split('\n')
banner()	
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
version = '1.1.2'

parser = argparse.ArgumentParser(description='Domain scan | v{}'.format(version))
parser.add_argument('url', help='Target URL')
parser.add_argument('--headers', help='Header Information', action='store_true')
#parser.add_argument('--sslinfo', help='SSL Certificate Information', action='store_true')
parser.add_argument('--whois', help='Whois Lookup', action='store_true')
#parser.add_argument('--crawl', help='Crawl Target', action='store_true')
#parser.add_argument('--dns', help='DNS Enumeration', action='store_true')
#parser.add_argument('--sub', help='Sub-Domain Enumeration', action='store_true')
#parser.add_argument('--trace', help='Traceroute', action='store_true')
#parser.add_argument('--dir', help='Directory Search', action='store_true')
#parser.add_argument('--ps', help='Fast Port Scan', action='store_true')
#parser.add_argument('--full', help='Full Recon', action='store_true')

ext_help = parser.add_argument_group('Extra Options')
ext_help.add_argument('-o', help='Export Output [ Default : txt ] [ Available : xml, csv ]')

try:
	args = parser.parse_args()
except SystemExit:
	os.remove(pid_path)
	sys.exit()

target = args.url
headinfo = args.headers
#sslinfo = args.sslinfo
whois = args.whois
#crawl = args.crawl
#dns = args.dns
#trace = args.trace
#dirrec = args.dir
#pscan = args.ps
#full = args.full
#threads = args.t
#tout = args.T
#wdlist = args.w
#redir = args.r
#sslv = args.s
#sslp = args.sp
#dserv = args.d
#filext = args.e
#subd = args.sub
#mode = args.m
#port = args.p
#tr_tout = args.tt
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

def banner():
	banner = r'''

 ___ _____    _____   _    _  _______ _   _ 
|_ _|_   _|  |__  /  / \  | |/ / ____| \ | |
 | |  | |_____ / /  / _ \ | ' /|  _| |  \| |
 | |  | |_____/ /_ / ___ \| . \| |___| |\  |
|___| |_|    /____/_/   \_\_|\_\_____|_| \_|'''

	print(G + banner + W + '\n')
	print(G + '[>]' + C + ' Created By : ' + W + 'IT-Zaken')
	print(G + '[>]' + C + ' Version    : ' + W + version + '\n')

def full_recon():
#	from scans.sslinfo import cert
#	from scans.crawler import crawler
	from modules.headers import headers
#	from scans.dns import dnsrec
#	from scans.traceroute import troute
	from scans.whois import whois_lookup
#	from scans.dirrec import hammer
#	from scans.portscan import ps
#	from scans.subdom import subdomains
	headers(target, output, data)
#	cert(hostname, sslp, output, data)
	whois_lookup(ip, output, data)
#	dnsrec(domain, output, data)
#	if type_ip == False:
#		subdomains(domain, tout, output, data, conf_path)
#	else:
#		pass
#	troute(ip, mode, port, tr_tout, output, data)
#	ps(ip, output, data)
#	crawler(target, output, data)
#	hammer(target, threads, tout, wdlist, redir, sslv, dserv, output, data, filext)

try:
	banner()

	if target.startswith(('http', 'https')) == False:
		print(R + '[-]' + C + ' Protocol Missing, Include ' + W + 'http://' + C + ' or ' + W + 'https://' + '\n')
		os.remove(pid_path)
		sys.exit()
	else:
		pass

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