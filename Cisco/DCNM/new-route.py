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

##### Settings from settings.ini
from configparser import ConfigParser
config = ConfigParser()

config.read('C:/Temp/Git/Cisco/DCNM/settings.ini')

dcnmuser = config.get('DCNM', 'dcnmuser')
dcnmpassword = config.get('DCNM', 'dcnmpassword')
dcnmserver = config.get('DCNM', 'dcnmserver')
######

uri = "/rest/control/policies/bulk-create"

logger = logging.getLogger()
logging.basicConfig(filename="new-route.log", filemode='a', format='%(asctime)s.%(msecs)03d %(levelname)s - %(funcName)s: %(message)s',  datefmt='%Y-%m-%d %H:%M:%S')
logger.setLevel(logging.DEBUG)
#logger.debug("This is a debug message")
#logger.info("For your info")
#logger.warning("This is a warning message")
#logger.error("This is an error message")
#logger.critical("This is a critical message")


parser = argparse.ArgumentParser(description='DCNM New IPv4 Route')

parser.add_argument("--v", required=True, type=str, help="VRF Name")
parser.add_argument("--p", required=True, type=ip_network, help="Prefix IPv4")
parser.add_argument("--n", required=True, type=ip_address, help="Next Hop")


args = parser.parse_args()

vrfName = args.v
prefix = args.p
nextHop = args.n

logger.info('Settings %s', args)

# Get Token
token = getRestToken(dcnmuser, dcnmpassword, dcnmserver)

#CYO
sCyo = """
{
    "source": "",
    "serialNumber": "FDO23281LWE,FDO23301646,FDO23310G4W,FDO23310G4G,FDO23270DEW,FDO23270DEF",
    "entityType": "SWITCH",
    "entityName": "SWITCH",
    "templateName": "vrf_static_route",
    "priority": "500",
    "nvPairs": {
        "VRF_NAME": "%s",
        "IP_PREFIX": "%s",
        "NEXT_HOP_IP": "%s"
    }
}
""" % (vrfName, prefix, nextHop)

cyoResult = DCNMPost(sCyo, uri, dcnmserver, token)
logger.info('Result CyrusOne: %s', cyoResult)
#IXN
sIXN= """
{
    "source": "",
    "serialNumber": "FDO23240C87,FDO2329188A,FDO2330163K,FDO23310G5H,FDO23310G5M,FDO23220EX6",
    "entityType": "SWITCH",
    "entityName": "SWITCH",
    "templateName": "vrf_static_route",
    "priority": "500",
    "nvPairs": {
        "VRF_NAME": "%s",
        "IP_PREFIX": "%s",
        "NEXT_HOP_IP": "%s"
    }
}

""" % (vrfName, prefix, nextHop)

ixnResult = DCNMPost(sIXN, uri, dcnmserver, token)
logger.info('Result InterXion: %s', ixnResult)
