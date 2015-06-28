#!/usr/bin/python
#Copyright [2015] Joerg Stephan <johe.stephan [@] outlook.com>

#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS,
#WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#See the License for the specific language governing permissions and
#limitations under the License.

import urllib
import urllib2
from optparse import OptionParser
import json
import hashlib
import os.path
import tempfile

def send_request(url, scanurl, token=get_token()):
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
    if os.path.isfile(tempfile.gettempdir() + "/IXFtoken"):
	    tokenf = open(tempfile.gettempdir + "/IXFtoken","r")
	    token = tokenf.readline()
    else:
	    url = "https://xforce-api.mybluemix.net:443/auth/anonymousToken"
	    data = urllib2.urlopen(url)
	    t = json.load(data)
	    tokenf = open(tempfile.gettempdir() + "/IXFtoken","w")
        token = str(t['token'])
        tokenf.write(token)
    return token 

def send_md5(filename, url, token=get_token()):
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

def get_malware_intel(file):
    send_md5(file, url+"/malware/")

def get_ip_intel(ip):
    apiurl = url + "/ipr/"
    send_request(apiurl, scanurl)
    apiurl = url + "/ipr/history/"
    send_request(apiurl, scanurl)
    apiurl = url + "/ipr/malware/"
    send_request(apiurl, scanurl)

def get_url_intel(url):
    apiurl = url + "/url/"
    scanurl = options.s_url
    send_request(apiurl, scanurl)

def get_url_malware_intel(url):
    apiurl = url + "/url/malware/" 
    scanurl = options.m_url
    send_request(apiurl, scanurl)

def get_cve_info(cve):
    apiurl = url + "/vulnerabilities/search/" 
    scanurl = options.s_cve
    send_request(apiurl, scanurl)

def get_xfid_info(xfid):
    send_request(url+"/vulnerabilities/", options.s_xfid)

HOMEfolder = os.path.dirname(os.path.realpath(__file__))

url = "https://xforce-api.mybluemix.net:443"
	
	

