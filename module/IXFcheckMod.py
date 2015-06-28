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

def send_request(url, scanurl):
	try:
		token=get_token()
		furl = url + urllib.quote(scanurl)
		htoken = "Bearer "+ token
		headers = {'Authorization': htoken,}
		request = urllib2.Request(furl, None, headers)
		data = urllib2.urlopen(request)
		jdata = json.loads(data.read())
		#print json.dumps(jdata, sort_keys=True, indent=3, separators=(',', ': '))
		return jdata
	except urllib2.HTTPError, e:
		print str(e)
		return None


def get_token():
    mytempfile = str(tempfile.gettempdir()) 
    mytempfile += "/IXFtoken"
    if os.path.isfile(mytempfile):
	    tokenf = open(mytempfile,"r")
	    token = tokenf.readline()
    else:
	    url = "https://xforce-api.mybluemix.net:443/auth/anonymousToken"
	    data = urllib2.urlopen(url)
	    t = json.load(data)
	    tokenf = open(mytempfile,"w")
            token = str(t['token'])
            tokenf.write(token)
    return token 

def send_md5(filename, url):
    try:
	token=get_token()
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

def get_ip_intel_artillery_strip(ip):
    apiurl = url + "/ipr/"
    jdata = send_request(apiurl, ip)
    CountryCode = jdata['geo']['countrycode']
    iscore = jdata['score']
    #print json.dumps(jdata, sort_keys=True, indent=3, separators=(',', ': '))
    
    apiurl = url + "/ipr/malware/"
    jdata = send_request(apiurl, ip)
    asmalware = jdata['malware']
    #print json.dumps(jdata, sort_keys=True, indent=3, separators=(',', ': '))
    return "Country: " + CountryCode + " Score: " + str(iscore) + " Malware: " + str(asmalware)


def get_ip_intel(ip):
    apiurl = url + "/ipr/"
    jdata = send_request(apiurl, ip)
    print json.dumps(jdata, sort_keys=True, indent=3, separators=(',', ': '))
    #apiurl = url + "/ipr/history/"
    #jdata = send_request(apiurl, ip)
    #print json.dumps(jdata, sort_keys=True, indent=3, separators=(',', ': '))
    apiurl = url + "/ipr/malware/"
    jdata = send_request(apiurl, ip)
    print json.dumps(jdata, sort_keys=True, indent=3, separators=(',', ': '))


def get_url_intel(s_url):
    apiurl = url + "/url/"
    scanurl = s_url
    send_request(apiurl, scanurl)

def get_url_malware_intel(s_url):
    apiurl = url + "/url/malware/" 
    scanurl = s_url
    send_request(apiurl, scanurl)

def get_cve_info(cve):
    apiurl = url + "/vulnerabilities/search/" 
    scanurl = cve
    send_request(apiurl, scanurl)

def get_xfid_info(xfid):
    send_request(url+"/vulnerabilities/", xfid)

HOMEfolder = os.path.dirname(os.path.realpath(__file__))

url = "https://xforce-api.mybluemix.net:443"
	
	

