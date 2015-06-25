#!/usr/bin/python

import simplejson
import urllib
import urllib2
from optparse import OptionParser
import json
import hashlib
import os.path

def send_request(url, scanurl, token):
	try:
		furl = url + urllib.quote(scanurl)
		print furl
		htoken = "Bearer "+ token
		headers = {'Authorization': htoken,}
		request = urllib2.Request(furl, None, headers)
		data = urllib2.urlopen(request)
		print json.dumps(json.loads(data.read()), sort_keys=True, indent=3, separators=(',', ': '))
		return 1
	except urllib2.HTTPError, e:
		print str(e)
		return 0



def get_token():
	url = "https://xforce-api.mybluemix.net:443/auth/anonymousToken"
	data = urllib2.urlopen(url)
	t = json.load(data)
	tokenf = open(HOMEfolder + "/token","w")
	tokenf.write(str(t['token']))
	return True 


def send_md5(filename, url, token):
	try:
		f = open(filename,"rb")
		md5 = hashlib.md5((f).read()).hexdigest()
		furl = url + md5
		htoken = "Bearer "+ token
		headers = {'Authorization': htoken,}
		request = urllib2.Request(furl, None, headers)
		data = urllib2.urlopen(request)
		print data.read()
		return 1
	except  urllib2.HTTPError, e:
		print str(e)
		return 0

parser = OptionParser()
parser.add_option("-u", "--url", dest="s_url", default=None, 
                  help="URL to be checked by Exchange IBM Xforce", metavar="scanurl")
parser.add_option("-m", "--malware", dest="m_url", default=None, 
                  help="Malware to be checked by Exchange IBM Xforce", metavar="scanurl")
parser.add_option("-f", "--file", dest="malfile" , default=None,
                  help="file (md5 hash) to be checked by Exchange IBM Xforce", metavar="filename")
parser.add_option("-x", "--xfid", dest="s_xfid" , default=None,
                  help="XFID to be used ", metavar="xfid")
parser.add_option("-c", "--cve", dest="s_cve" , default=None,
                  help="CVE, BID, US-Cert, UV#, RHSA id to be searched ", metavar="cve-xxx-xxx")
parser.add_option("-i", "--ip", dest="s_ip" , default=None,
                  help="ip to be checked", metavar="ipaddress")

(options, args) = parser.parse_args()


HOMEfolder = os.path.dirname(os.path.realpath(__file__))

url = "https://xforce-api.mybluemix.net:443"

if os.path.isfile("./token"):
	tokenf = open(HOMEfolder + "/token","r")
	token = tokenf.readline()
else:
	get_token()
	tokenf = open(HOMEfolder + "/token","r")
	token = tokenf.readline()

if ( options.s_url is not None ):
	apiurl = url + "/url/"
	scanurl = options.s_url
	send_request(apiurl, scanurl, token)
elif ( options.m_url is not None ):
	apiurl = url + "/url/malware/" 
	scanurl = options.m_url
	send_request(apiurl, scanurl, token)
elif ( options.s_cve is not None ):
	apiurl = url + "/vulnerabilities/search/" 
	scanurl = options.s_cve
	send_request(apiurl, scanurl, token)
elif (options.s_ip is not None):
	scanurl = options.s_ip
	apiurl = url + "/ipr/"
	send_request(apiurl, scanurl, token)
	apiurl = url + "/ipr/history/"
        send_request(apiurl, scanurl, token)
	apiurl = url + "/ipr/malware/"
        send_request(apiurl, scanurl, token)
elif (options.malfile is not None ):
	send_md5(options.malfile, url+"/malware/", token)
elif (options.s_xfid is not None ):
	send_request(url+"/vulnerabilities/", options.s_xfid, token)
	

