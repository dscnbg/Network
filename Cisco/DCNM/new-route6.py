import http.client
import ssl
import base64
import string
import json
import argparse
import ipaddress

import logging
import logging.handlers

from ipaddress import IPv6Address
from ipaddress import IPv6Network

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
logging.basicConfig(filename="new-route6.log", filemode='a', format='%(asctime)s.%(msecs)03d %(levelname)s - %(funcName)s: %(message)s',  datefmt='%Y-%m-%d %H:%M:%S')
logger.setLevel(logging.DEBUG)
#logger.debug("This is a debug message")
#logger.info("For your info")
#logger.warning("This is a warning message")
#logger.error("This is an error message")
#logger.critical("This is a critical message")


parser = argparse.ArgumentParser(description='DCNM New IPv6 Route')

parser.add_argument("--v", required=True, type=str, help="VRF Name")
parser.add_argument("--p", required=True, type=IPv6Network, help="Prefix IPv6")
parser.add_argument("--n", required=True, type=IPv6Address, help="Next Hop")
parser.add_argument("--r", required=True, type=str, help="Route Name")
parser.add_argument("--t", required=True, type=int, help="Route Tag")


args = parser.parse_args()

vrfName = args.v
prefix = args.p
nextHop = args.n
rname = args.r
tag = args.t

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
    "templateName": "dop_static_named_v6",
    "priority": "500",
    "nvPairs": {
        "VRF_NAME": "%s",
        "IPV6_PREFIX": "%s",
        "NEXT_HOP_IPV6": "%s",
        "RNAME": "%s",
        "TAG": "%s"
    }
}
""" % (vrfName, prefix, nextHop, rname, tag)

cyoResult = DCNMPost(sCyo, uri, dcnmserver, token)
logger.info('Result CyrusOne: %s', cyoResult)
#IXN
sIXN= """
{
    "source": "",
    "serialNumber": "FDO23240C87,FDO2329188A,FDO2330163K,FDO23310G5H,FDO23310G5M,FDO23220EX6",
    "entityType": "SWITCH",
    "entityName": "SWITCH",
    "templateName": "dop_static_named_v6",
    "priority": "500",
    "nvPairs": {
        "VRF_NAME": "%s",
        "IPV6_PREFIX": "%s",
        "NEXT_HOP_IPV6": "%s",
        "RNAME": "%s",
        "TAG": "%s"
    }
}
""" % (vrfName, prefix, nextHop, rname, tag)
#print(sCyo)
ixnResult = DCNMPost(sIXN, uri, dcnmserver, token)
logger.info('Result InterXion: %s', ixnResult)
