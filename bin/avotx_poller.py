import urllib2
import re
import socket
import sys
import time
import ConfigParser

import time

TIME_FORMAT_ISO8601 = '%Y-%m-%dT%H:%M:%S'

def timestamp():
    return time.strftime(TIME_FORMAT_ISO8601)

config_file = "./avotx_poller.cfg"

socket.setdefaulttimeout(35)
config = ConfigParser.RawConfigParser()

FACILITY = {
        'kern': 0, 'user': 1, 'mail': 2, 'daemon': 3,
        'auth': 4, 'syslog': 5, 'lpr': 6, 'news': 7,
        'uucp': 8, 'cron': 9, 'authpriv': 10, 'ftp': 11,
        'local0': 16, 'local1': 17, 'local2': 18, 'local3': 19,
        'local4': 20, 'local5': 21, 'local6': 22, 'local7': 23,
}

LEVEL = {
        'emerg': 0, 'alert':1, 'crit': 2, 'err': 3,
        'warning': 4, 'notice': 5, 'info': 6, 'debug': 7
}

def get_url(url):
	content = urllib2.urlopen(url).read()
	return content
	
def check_reputation_format(ln):
	r = re.compile("^[+-]?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}#\d\d?#\d\d?#.*#.*#.*#.*#.*$")
	if ln != "":
		if not r.match(ln):
			return False
	return True

def get_remote_rep_rev(rep_serv):
	data = get_url("%sreputation.rev" % rep_serv)
	if data:
		return data
	else:
		return None

def get_remote_patch(rep_serv, revision):
	patch = get_url("%srevisions/reputation.data_%s" % (rep_serv, revision))
	rev = get_url("%sreputation.rev" % rep_serv)
	if rev != None:
		config.set('main', 'revision', rev)
		with open(config_file, 'wb') as configfile:
		    config.write(configfile)
	return patch

def download_reputation_database(rep_serv):
	try:
		data = get_url("%sreputation.data" % rep_serv)			
		rev = get_url("%sreputation.rev" % rep_serv)
		if rev != None:
			config.set('main', 'revision', rev)
			with open(config_file, 'wb') as configfile:
			    config.write(configfile)
		return data
	except:
		print "{0} Error-update: Error downloading database from server".format(timestamp())
		return None

config.read(config_file)

if config.getboolean('proxy', 'enable'):
	print "{0} Using Proxy".format(timestamp())
	user = config.get('proxy', 'user')
	password = config.get('proxy', 'password')
	proxy_host = config.get('proxy', 'host')
	proxy_port = config.getint('proxy', 'port')
	proxy_support = urllib2.ProxyHandler({"http" : "http://%s:%s@%s:%d" % (user, password, proxy_host, proxy_port)})
	opener = urllib2.build_opener(proxy_support, urllib2.HTTPHandler)
	urllib2.install_opener(opener)

def main():
	reputation_server = config.get('main', 'reputation_server')
	avotx_poller_rev = config.get('main', 'avotx_poller_rev')

	try:
		remote_rev = get_url("%sreputation.rev" % reputation_server).replace("\n","")
		print "{0} Server data rev is {1}".format(timestamp(), remote_rev)
	except:
		print "{0} Error fetching server rev".format(timestamp())

	local_rev = config.get('main', 'revision')
	print "{0} Local rev is {1}".format(timestamp(), local_rev)
	if remote_rev != local_rev:
		print "{0} Updating data from server".format(timestamp())
		try:
			data = get_remote_patch(reputation_server, local_rev)
		except urllib2.HTTPError:
			print "{0} Downloading complete database".format(timestamp())
			data = download_reputation_database(reputation_server)
		
		black_activities = config.get('fields', 'ignore_activities')
		b_acts = None
		if black_activities and black_activities != "":
			b_acts = black_activities.split(",")
			
		if data:
			for d in data.split("\n"):
				if check_reputation_format(d) and d != "":
					if d[0] == "-":
						continue
					if d[0] == "+":
						d = d[1:]
					fs = d.split("#")
					if len(fs) == 8:
						#Check parameters
						min_priority = config.getint('fields', 'min_priority')
						min_reliability = config.getint('fields', 'min_reliability')
						rel = int(fs[1])
						prio = int(fs[2])
						if min_priority <= prio and min_reliability <= rel:
							#Check activities
							send = True
							if b_acts:
								for a in b_acts:
									if a == fs[3]:
										send = False
							if send:
								#CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
								splunk_event = "avotxSource=AlienvaultOTX; SuspiciousHost={0}; message=\"{1}\"; refurl=http://labs.alienvault.com/labs/index.php/projects/open-source-ip-reputation-portal/information-about-ip/?ip={2};".format(fs[0],fs[3],fs[0])
								print "{0} avotx_poller_rev={1}; {2}".format(timestamp(), avotx_poller_rev, splunk_event)
								#syslog(cef)
		else:
			print "{0} There was a problem when contacting the remote server".format(timestamp())

						
if __name__ == '__main__':
	main()




