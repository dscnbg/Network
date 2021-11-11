from phpipam_client import PhpIpamClient, GET, PATCH, POST
import json

import logging
import logging.handlers

import argparse

from functions import Cb3Vlan

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Logging


# Argument Parser aufruf



# Array um die Netzwerke aufzunehmen
networks = []

##### Settings from settings.ini
from configparser import ConfigParser
config = ConfigParser()

config.read('C:/Temp/Git/Cisco/DCNM/settings.ini')

dcnmuser = config.get('DCNM', 'dcnmuser')
dcnmpassword = config.get('DCNM', 'dcnmpassword')
dcnmserver = config.get('DCNM', 'dcnmserver')
######


# DCNM Token abholen
# token = getRestToken(dcnmuser, dcnmpassword, dcnmserver)

# ipam Konfiguration
ipam = PhpIpamClient(
    url='https://ipam.consinto.com',
    app_id='network',
    username=dcnmuser,
    ssl_verify=False,
    password=dcnmpassword,
    user_agent='myapiclient', # custom user-agent header
)

beginn = 3708
ende = 3800
for x in range(beginn, ende):
    IPAMvlans = ipam.post('/vlan/', {
        'domainId': 57,
        'name': 'PLATZHALTER-DMZ',
        'number': x,
        'description': 'PLATZHALTER-DMZ'
    })
