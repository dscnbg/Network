import http.client
import ssl
import base64
import string
import json
import argparse
import ipaddress

import logging
import logging.handlers

from ipaddress import ip_address
from ipaddress import ip_network

from functions import getRestToken
from functions import DCNMPost
from functions import DCNMPost2
from functions import DCNMget

from functions import vrfVergleich


##### Settings from settings.ini
from configparser import ConfigParser
config = ConfigParser()

config.read('C:/Temp/Git/Cisco/DCNM/settings.ini')

dcnmuser = config.get('DCNM', 'dcnmuser')
dcnmpassword = config.get('DCNM', 'dcnmpassword')
dcnmserver = config.get('DCNM', 'dcnmserver')
######

uri = "/rest/top-down/fabrics/MSD001/networks"

logger = logging.getLogger()
logging.basicConfig(filename="new-vlan.log", filemode='a', format='%(asctime)s.%(msecs)03d %(levelname)s - %(funcName)s: %(message)s',  datefmt='%Y-%m-%d %H:%M:%S')
logger.setLevel(logging.DEBUG)
#logger.debug("This is a debug message")
#logger.info("For your info")
#logger.warning("This is a warning message")
#logger.error("This is an error message")
#logger.critical("This is a critical message")


parser = argparse.ArgumentParser(description='DCNM New IPv4 Route')

parser.add_argument("--v", required=True, type=str, help="VRF Name")
#parser.add_argument("--i", required=True, type=str, help="VLAN ID")
#parser.add_argument("--n", required=True, type=str, help="VLAN Name")


args = parser.parse_args()

vrfName = args.v
#vlanId = args.i
#vlanName = args.n

#logger.info('Settings %s', args)

# Get Token
token = getRestToken(dcnmuser, dcnmpassword, dcnmserver)

uri = "/rest/top-down/v2/fabrics/MSD001/vrfs"

result = DCNMget(uri, dcnmserver, token)

vergleich = []

#print(result)
for results in result:
    wip = results['vrfName']
    vergleich.append(vrfVergleich(wip))

for vgl in vergleich:
    if (vrfName.upper() == vgl.vergleich):
        print(vgl.name)
    