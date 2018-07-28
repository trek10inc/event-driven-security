#!/usr/bin/python

import urllib2
import re
import os
import boto3
from StringIO import StringIO
import gzip

ip_set_id = os.getenv('IPSET', 'no-ipset') # Was originally in a CFT, this needs to be passed in with an env variable now
url = "https://isc.sans.edu/block.txt"

waf_client = boto3.client('waf')

#
# Source the bad IPs from the SANS service.  
#
def getSansBadIps(url):

    # Uncomment for testing...
    # return ['142.77.69.0/24', '182.100.27.0/24', '61.240.144.0/24', '222.174.5.0/24', 
    # '222.186.21.0/24', '117.34.74.0/24', '62.138.6.0/24', '209.126.127.0/24', 
    # '69.64.57.0/24', '62.138.3.0/24', '209.126.111.0/24', '172.93.97.0/24', 
    # '91.213.33.0/24', '119.189.108.0/24', '83.220.172.0/24', '14.32.80.0/24', 
    # '14.43.137.0/24', '118.39.182.0/24', '210.218.188.0/24', '39.67.160.0/24']

    ret = []
    headers = {'User-Agent': 'lambda-python-sec-script',
               'Accept-encoding': 'gzip'}
    
    try:
        request = urllib2.Request(url, headers=headers)
        response = urllib2.urlopen(request)
        
    except urllib2.HTTPError, e:
        print("Failed to get get web resource - {}.".format(e.code))
        return False
         
    else:
        if (response.info().get('Content-Encoding') == 'gzip'):
            buf = StringIO( response.read())
            f = gzip.GzipFile(fileobj=buf)
            contents = f.read()    
        else:
            contents = response.read()
        
        #print(contents)
        lines = contents.split("\n")

        for line in lines:
            if (len(line) > 0):
                if (line[0] != "#"):
                    parts = line.split("\t")
                    if re.match(r"(?:\d{1,3}\.){3}\d{1,3}(?:/\d\d?)?", parts[0]):
                        ret.append("{}/{}".format(parts[0], parts[2]))
        
        return ret
#
# Source the values from the current WAF IPSet  
#
def getCurrentIPSet(ip_set_id):

    ret = []
    
    try:
        ip_set = waf_client.get_ip_set(
            IPSetId=ip_set_id
        )
        
    except:
        print("Failed to get get IPSet")
        return False
        
    else:
        for item in  ip_set['IPSet']['IPSetDescriptors']:
            ret.append(item['Value'])
    
    return ret

#
# Format a dict for the update statment  
#
def createUpdatesList( cidr_to_remove, cidr_to_add ):
    
    ret = []
    for cidr in cidr_to_remove:
        ret.append( {'Action': 'DELETE','IPSetDescriptor': {'Type': 'IPV4', 'Value': cidr}} )

    for cidr in cidr_to_add:
        ret.append( {'Action': 'INSERT','IPSetDescriptor': {'Type': 'IPV4', 'Value': cidr}} )    
    
    return ret
     
#
# Send update to AWS WAF  
#
def updateIPSet( IPSet, updatesList ):

    change_token = waf_client.get_change_token()

    print("Change token: {}".format(change_token['ChangeToken']))
    
    response_token = waf_client.update_ip_set(
        IPSetId=IPSet,
        ChangeToken=change_token['ChangeToken'],
        Updates=updatesList
    )
    
    return waf_client.get_change_token_status(ChangeToken=response_token['ChangeToken'])

#
# Lambda Handler  
#
def handler( event, context ):    

    print("Starting update...")
    
    sans_bad_ips = getSansBadIps(url)
    print("Found {} CIDRs from SANS".format( len(sans_bad_ips) ))
    print(sans_bad_ips)

    current_ip_set = getCurrentIPSet(ip_set_id)
    print("Found {} CIDRs from current IPSet".format( len(current_ip_set) ))
    print(current_ip_set)

    cidr_to_remove = [ i for i in current_ip_set if i not in sans_bad_ips]
    print("There are {} CIDRs to REMOVE from current IPSet".format( len(cidr_to_remove) ))
    print(cidr_to_remove)

    cidr_to_add = [ i for i in sans_bad_ips if i not in current_ip_set]
    print("There are {} CIDRs to add ADD to current IPSet".format( len(cidr_to_add) ))
    print(cidr_to_add)

    updatesList = (createUpdatesList(cidr_to_remove, cidr_to_add))

    if len(updatesList):
        print("Sending update to WAF...")
        return(updateIPSet( ip_set_id, updatesList ))
    else:
        return("No changes to be made.")
    print("Done.")
    
handler(False, False)
