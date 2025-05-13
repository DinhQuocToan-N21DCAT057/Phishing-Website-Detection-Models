#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Mon Jul 27 17:58:48 2020

@author: hannousse
"""
from bs4 import BeautifulSoup
import requests
import re
from datetime import datetime, timezone
from time import time
import whois


#################################################################################################################################
#               Datetime list converter
#################################################################################################################################

def normalize_datetime_list(date_list):
    """Convert a list of mixed naive and aware datetimes to a list of aware datetimes in UTC."""
    if not date_list:
        return []

    normalized_dates = []
    for dt in date_list:
        if dt is None:
            continue
        # Convert naive datetimes to aware ones (UTC)
        if dt.tzinfo is None:
            normalized_dates.append(dt.replace(tzinfo=timezone.utc))
        else:
            normalized_dates.append(dt.astimezone(timezone.utc))

    return normalized_dates


#################################################################################################################################
#               Domain registration age 
#################################################################################################################################

def domain_registration_length(domain):
    try:
        res = whois.whois(domain)
        expiration_date = res.expiration_date

        # Handle case where expiration_date is a list
        if isinstance(expiration_date, list):
            # Normalize all dates to make them timezone-aware with UTC
            normalized_dates = normalize_datetime_list(expiration_date)
            if not normalized_dates:
                return 0  # No valid data
            expiration_date = min(normalized_dates)
        elif expiration_date is None:
            return 0  # No data
        elif expiration_date.tzinfo is None:
            # Single naive datetime
            expiration_date = expiration_date.replace(tzinfo=timezone.utc)
        else:
            # Single aware datetime but potentially in a different timezone
            expiration_date = expiration_date.astimezone(timezone.utc)

        # Get current time in UTC
        now = datetime.now(timezone.utc)

        length_days = (expiration_date - now).days
        return length_days if length_days >= 0 else 0
    except Exception as e:
        print(f"[WHOIS ERROR] domain_registration_length({domain}): {e}")
        return -1

def domain_registration_length1(domain):
    v1 = -1
    v2 = -1
    try:
        host = whois.whois(domain)
        hostname = host.domain_name
        expiration_date = host.expiration_date
        today = time.strftime('%Y-%m-%d')
        today = datetime.strptime(today, '%Y-%m-%d')
        if type(hostname) == list:
            for host in hostname:
                if re.search(host.lower(), domain):
                    v1 = 0
            v1= 1
        else:
            if re.search(hostname.lower(), domain):
                v1 = 0
            else:
                v1= 1
        if expiration_date:
            if type(expiration_date) == list:
                expiration_date = min(expiration_date)
            return abs((expiration_date - today).days)
        else:
            v2= 0
    except:
        v1 = 1
        v2 = -1
        return v1, v2
    return v1, v2

#################################################################################################################################
#               Domain recognized by WHOIS
#################################################################################################################################

 
def whois_registered_domain(domain):
    try:
        hostname = whois.whois(domain).domain_name
        if type(hostname) == list:
            for host in hostname:
                if re.search(host.lower(), domain):
                    return 0
            return 1
        else:
            if re.search(hostname.lower(), domain):
                return 0
            else:
                return 1     
    except:
        return 1

#################################################################################################################################
#               Get web traffic (Page Rank) (Not working) (Insert value manually if needed)
#################################################################################################################################
import urllib

def web_traffic(short_url):
        try:
            rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + short_url).read(), "xml").find("REACH")['RANK']
        except:
            return 0
        return int(rank)



#################################################################################################################################
#               Domain age of a url
#################################################################################################################################

def domain_age(domain):
    try:
        res = whois.whois(domain)
        creation_date = res.creation_date

        # Handle case where creation_date is a list
        if isinstance(creation_date, list):
            # Normalize all dates to make them timezone-aware with UTC
            normalized_dates = normalize_datetime_list(creation_date)
            if not normalized_dates:
                return -2  # No valid data
            creation_date = min(normalized_dates)
        elif creation_date is None:
            return -2  # No data
        elif creation_date.tzinfo is None:
            # Single naive datetime
            creation_date = creation_date.replace(tzinfo=timezone.utc)
        else:
            # Single aware datetime but potentially in a different timezone
            creation_date = creation_date.astimezone(timezone.utc)

        # Get current time in UTC
        now = datetime.now(timezone.utc)

        age_days = (now - creation_date).days
        return age_days if age_days >= 0 else -2
    except Exception as e:
        print(f"[WHOIS ERROR] domain_age({domain}): {e}")
        return -1



#################################################################################################################################
#               Global rank
#################################################################################################################################

def global_rank(domain):
    rank_checker_response = requests.post("https://www.checkpagerank.net/index.php", {
        "name": domain
    })
    
    try:
        return int(re.findall(r"Global Rank: ([0-9]+)", rank_checker_response.text)[0])
    except:
        return -1


#################################################################################################################################
#               Google index
#################################################################################################################################


from urllib.parse import urlencode

def google_index(url):
    #time.sleep(.6)
    user_agent =  'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36'
    headers = {'User-Agent' : user_agent}
    query = {'q': 'site:' + url}
    google = "https://www.google.com/search?" + urlencode(query)
    data = requests.get(google, headers=headers)
    data.encoding = 'ISO-8859-1'
    soup = BeautifulSoup(str(data.content), "html.parser")
    try:
        if 'Our systems have detected unusual traffic from your computer network.' in str(soup):
            return -1
        check = soup.find(id="rso").find("div").find("div").find("a")
        #print(check)
        if check and check['href']:
            return 0
        else:
            return 1
        
    except AttributeError:
        return 1

#print(google_index('http://www.google.com'))
#################################################################################################################################
#               DNSRecord  expiration length
#################################################################################################################################

import dns.resolver

def dns_record(domain):
    try:
        nameservers = dns.resolver.query(domain,'NS')
        if len(nameservers)>0:
            return 0
        else:
            return 1
    except:
        return 1

#################################################################################################################################
#               Page Rank from OPR
#################################################################################################################################


def page_rank(key, domain):
    url = 'https://openpagerank.com/api/v1.0/getPageRank?domains%5B0%5D=' + domain
    try:
        request = requests.get(url, headers={'API-OPR':key})
        result = request.json()
        result = result['response'][0]['page_rank_integer']
        if result:
            return result
        else:
            return 0
    except:
        return -1


