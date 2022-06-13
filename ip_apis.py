#! /usr/bin/env python
#  -*- coding: utf-8 -*-

import csv
import json
import os
import requests
import sys

from pprint import pprint

# Import API keys as environment variables.
VT_APIKEY = os.getenv('VT_API_KEY')
if VT_APIKEY is None:
    sys.exit('VT_API_KEY not found in environment variables.')

IPINFO_APIKEY = os.getenv('IPINFO_API_KEY')
if IPINFO_APIKEY is None:
    sys.exit('IPINFO_API_KEY not found in environment variables.')

VPNAPI_APIKEY = os.getenv('VPNAPI_API_KEY')
if VPNAPI_APIKEY is None:
    sys.exit('VPNAPI_API_KEY not found in environment variables.')

# Send scan request using VT API.    
def vt_domain_scan(domains):
    results = []
    if not isinstance(domains, list):
        domains = [domains]
    for domain in domains:
        # Prepare the request.
        url = 'https://www.virustotal.com/vtapi/v2/url/scan'
        params = {'apikey': VT_APIKEY, 'url': domain}
        
        # Send request and print any errors.
        try:
            response = requests.post(url, params=params)
            
            # Process response to the request.
            if response.status_code != 200:
                print('{} status code returned for {}.'.format(str(response.status_code), domain))
            else:
                results.append(domain)
                print('{}/{} domains queued successfully.'.format(len(results), len(domains)), end='\r')
        except Exception as e:
            print(str(e))
          
    print()
    return results

# Fetch VT API scan results.
def vt_results(domains):
    results = []
    if not isinstance(domains, list):
        domains = [domains]
    for domain in domains:
        # Prepare the request.
        url = 'https://www.virustotal.com/vtapi/v2/url/report'
        params = {'apikey': VT_APIKEY, 'resource': domain}
        
        # Send request and print any errors.
        try:
            response = requests.post(url, params=params)
            results.append(response.json())
        except Exception as e:
            print(str(e))    
    return results

# Fetch ipinfo data.
def ipinfo_results(domains):
    results = []
    if not isinstance(domains, list):
        domains = [domains]
    for domain in domains:
        #Prepare the request.
        url = 'http://ipinfo.io/{}?token={}'.format(domain, IPINFO_APIKEY)

        # Send request and print any errors.
        try:
            response = requests.get(url)
            results.append(response.json())
        except Exception as e:
            print(str(e))
    return results

# Fetch vpnapi data.
def vpnapi_results(domains):
    results = []
    if not isinstance(domains, list):
        domains = [domains]
    for domain in domains:
        #Prepare the request.
        url = 'https://vpnapi.io/api/{}?key={}'.format(domain, VPNAPI_APIKEY)

        # Send request and print any errors.
        try:
            response = requests.get(url)
            results.append(response.json())
        except Exception as e:
            print(str(e))
    return results    
