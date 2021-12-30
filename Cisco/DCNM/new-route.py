import http.client
import ssl
import base64
import string
import json
import argparse
import ipaddress
import sys
import logging
import logging.handlers

from ipaddress import ip_address
from ipaddress import ip_network

from functions import getRestToken, getVRF
from functions import DCNMPost, DCNMAuth, AuthenticateDCNM

##### Settings from settings.ini

auth = AuthenticateDCNM()

CBLACK  = '\33[30m'
CRED    = '\33[31m'
CGREEN  = '\33[32m'
CYELLOW = '\33[33m'
CBLUE   = '\33[34m'
CVIOLET = '\33[35m'
CBEIGE  = '\33[36m'
CWHITE  = '\33[37m'
CEND = '\033[0m'

# Get Token

token = getRestToken(auth.username, auth.password, auth.serverip)

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
parser.add_argument("--r", required=True, type=str, help="Route Name - wenn auf Ziel VRF Name gesetzt, ist kein Tag noetig")
parser.add_argument("--t", help='Route Tag', action='store', type=str, nargs='?')


args = parser.parse_args()

vrfName = args.v
prefix = args.p
nextHop = args.n
rname = args.r
tag = False
if args.t:
    tag = args.t
else:
    # das passende Tag aus dem DCNM holen
    vrfs = getVRF(auth.serverip, token)
    for vrf in vrfs:
        if (vrf['vrfName'].upper() == rname.upper()):
            tag = vrf['vrfId']
if not tag:
    for vrf in vrfs:
        print("{0} {1}".format(vrf['vrfName'], vrf['vrfId']))
    print(CRED + "VRF NOT FOUND - SEE POSSIBLE VALUES ABOVE" + CEND)
    sys.exit()

logger.info('Settings %s', args)

#CYO
sCyo = """
{
    "source": "",
    "serialNumber": "FDO23281LWE,FDO23301646,FDO23310G4W,FDO23310G4G",
    "entityType": "SWITCH",
    "entityName": "SWITCH",
    "templateName": "dop_static_named_v4",
    "priority": "500",
    "nvPairs": {
        "VRF_NAME": "%s",
        "IP_PREFIX": "%s",
        "NEXT_HOP_IP": "%s",
        "RNAME": "%s",
        "TAG": "%s"
    }
}
""" % (vrfName, prefix, nextHop, rname, tag)

cyoResult = DCNMPost(sCyo, uri, auth.serverip, token)
logger.info('Result CyrusOne: %s', cyoResult)
#IXN
sIXN= """
{
    "source": "",
    "serialNumber": "FDO2329188A,FDO2330163K,FDO23310G5M,FDO23310G5H",
    "entityType": "SWITCH",
    "entityName": "SWITCH",
    "templateName": "dop_static_named_v4",
    "priority": "500",
    "nvPairs": {
        "VRF_NAME": "%s",
        "IP_PREFIX": "%s",
        "NEXT_HOP_IP": "%s",
        "RNAME": "%s",
        "TAG": "%s"
    }
}

""" % (vrfName, prefix, nextHop, rname, tag)

ixnResult = DCNMPost(sIXN, uri, auth.serverip, token)
logger.info('Result InterXion: %s', ixnResult)
