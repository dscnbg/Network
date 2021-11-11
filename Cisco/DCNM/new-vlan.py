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

from functions import getRestToken
from functions import DCNMPost
from functions import DCNMPost2
from functions import returnVRF


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
parser.add_argument("--i", required=True, type=str, help="VLAN ID")
parser.add_argument("--n", required=True, type=str, help="VLAN Name")


args = parser.parse_args()

vrfName = args.v
vlanId = args.i
vlanName = args.n

logger.info('Settings %s', args)

# Get Token
token = getRestToken(dcnmuser, dcnmpassword, dcnmserver)

vrfName = returnVRF(vrfName, dcnmserver, token)

if vrfName == 0:
    sys.exit("VRF Fehlerhaft")

leer = ""
uri2 = "/rest/managed-pool/fabrics/MSD001/segments/ids"
segment = DCNMPost(leer, uri2, dcnmserver, token)
segment = segment["segmentId"]

nullstring = None

# Create VLAN
nested = {
    "gatewayIpAddress":"",
    "gatewayIpV6Address":"",
    "vlanName":vlanName,
    "intfDescription":vlanName,
    "mtu":"",
    "secondaryGW1":"",
    "secondaryGW2":"",
    "suppressArp":"false",
    "rtBothAuto":"false",
    "tag":"12345",
    "vrfName":vrfName,
    "isLayer2Only":"false",
    "nveId":"1",
    "vlanId":vlanId,
    "segmentId":segment, 
    "networkName":vlanName
}
#nested = json.dumps(nested)

createVLAN = {
    "fabric":"MSD001",
    "vrf":vrfName,
    "networkName":vlanName,
    "displayName":vlanName,
    "networkId":segment,
    "networkTemplateConfig":nested,
    "networkTemplate":"Default_Network_Universal",
    "networkExtensionTemplate":"Default_Network_Extension_Universal",
    "source":nullstring,
    "interfaceGroups": "",
    "tenantName": nullstring,
    "serviceNetworkTemplate":nullstring
}

createVLAN = json.dumps(createVLAN)

# POST
logger.info('VLAN: %s', createVLAN)
uri = "/rest/top-down/v2/fabrics/MSD001/networks"

res = DCNMPost2(createVLAN, uri, dcnmserver, token)
logger.info('Result: %s', res.status)
logger.info('Result: %s', res.reason)
#logger.info('Result: %s', res.content)
#print(res)
#print(createVLAN)
# Attach everywhere

attach = """
[
    {
        "lanAttachList": [
            {
                "switchPorts": "",
                "detachSwitchPorts": "",
                "dot1QVlan": 0,
                "untagged": false,
                "fabric": "DOP-FAB-DECYO001",
                "networkName": "%s",
                "serialNumber": "FDO23281LWE",
                "vlan": 0,
                "deployment": true,
                "extensionValues": "",
                "instanceValues": ""
            },
            {
                "switchPorts": "",
                "detachSwitchPorts": "",
                "dot1QVlan": 0,
                "untagged": false,
                "fabric": "DOP-FAB-DEIXN001",
                "networkName": "%s",
                "serialNumber": "FDO23240C87",
                "vlan": 0,
                "deployment": true,
                "extensionValues": "",
                "instanceValues": ""
            },
            {
                "switchPorts": "",
                "detachSwitchPorts": "",
                "dot1QVlan": 0,
                "untagged": false,
                "fabric": "FAB-DENUE001",
                "networkName": "%s",
                "serialNumber": "FDO2330165H",
                "vlan": 0,
                "deployment": true,
                "extensionValues": "",
                "instanceValues": ""
            },
            {
                "switchPorts": "",
                "detachSwitchPorts": "",
                "dot1QVlan": 0,
                "untagged": false,
                "fabric": "DOP-FAB-DEIXN001",
                "networkName": "%s",
                "serialNumber": "FDO2329188A",
                "vlan": 0,
                "deployment": true,
                "extensionValues": "",
                "instanceValues": ""
            },
            {
                "switchPorts": "",
                "detachSwitchPorts": "",
                "dot1QVlan": 0,
                "untagged": false,
                "fabric": "DOP-FAB-DECYO001",
                "networkName": "%s",
                "serialNumber": "FDO23310G4G",
                "vlan": 0,
                "deployment": true,
                "extensionValues": "",
                "instanceValues": ""
            },
            {
                "switchPorts": "",
                "detachSwitchPorts": "",
                "dot1QVlan": 0,
                "untagged": false,
                "fabric": "DOP-FAB-DEIXN001",
                "networkName": "%s",
                "serialNumber": "FDO23310G5H",
                "vlan": 0,
                "deployment": true,
                "extensionValues": "",
                "instanceValues": ""
            },
            {
                "switchPorts": "",
                "detachSwitchPorts": "",
                "dot1QVlan": 0,
                "untagged": false,
                "fabric": "DOP-FAB-DEIXN001",
                "networkName": "%s",
                "serialNumber": "FDO2330163K",
                "vlan": 0,
                "deployment": true,
                "extensionValues": "",
                "instanceValues": ""
            },
            {
                "switchPorts": "",
                "detachSwitchPorts": "",
                "dot1QVlan": 0,
                "untagged": false,
                "fabric": "DOP-FAB-DECYO001",
                "networkName": "%s",
                "serialNumber": "FDO23270DEW",
                "vlan": 0,
                "deployment": true,
                "extensionValues": "",
                "instanceValues": ""
            },
            {
                "switchPorts": "",
                "detachSwitchPorts": "",
                "dot1QVlan": 0,
                "untagged": false,
                "fabric": "DOP-FAB-DEIXN001",
                "networkName": "%s",
                "serialNumber": "FDO23310G5M",
                "vlan": 0,
                "deployment": true,
                "extensionValues": "",
                "instanceValues": ""
            },
            {
                "switchPorts": "",
                "detachSwitchPorts": "",
                "dot1QVlan": 0,
                "untagged": false,
                "fabric": "DOP-FAB-DEIXN001",
                "networkName": "%s",
                "serialNumber": "FDO23220EX6",
                "vlan": 0,
                "deployment": true,
                "extensionValues": "",
                "instanceValues": ""
            },
            {
                "switchPorts": "",
                "detachSwitchPorts": "",
                "dot1QVlan": 0,
                "untagged": false,
                "fabric": "DOP-FAB-DECYO001",
                "networkName": "%s",
                "serialNumber": "FDO23301646",
                "vlan": 0,
                "deployment": true,
                "extensionValues": "",
                "instanceValues": ""
            },
            {
                "switchPorts": "",
                "detachSwitchPorts": "",
                "dot1QVlan": 0,
                "untagged": false,
                "fabric": "FAB-DENUE001",
                "networkName": "%s",
                "serialNumber": "FDO23310G63",
                "vlan": 0,
                "deployment": true,
                "extensionValues": "",
                "instanceValues": ""
            },
            {
                "switchPorts": "",
                "detachSwitchPorts": "",
                "dot1QVlan": 0,
                "untagged": false,
                "fabric": "FAB-DENUE001",
                "networkName": "%s",
                "serialNumber": "FDO2330165T",
                "vlan": 0,
                "deployment": true,
                "extensionValues": "",
                "instanceValues": ""
            },
            {
                "switchPorts": "",
                "detachSwitchPorts": "",
                "dot1QVlan": 0,
                "untagged": false,
                "fabric": "DOP-FAB-DECYO001",
                "networkName": "%s",
                "serialNumber": "FDO23310G4W",
                "vlan": 0,
                "deployment": true,
                "extensionValues": "",
                "instanceValues": ""
            },
            {
                "switchPorts": "",
                "detachSwitchPorts": "",
                "dot1QVlan": 0,
                "untagged": false,
                "fabric": "FAB-DENUE001",
                "networkName": "%s",
                "serialNumber": "FDO23310G67",
                "vlan": 0,
                "deployment": true,
                "extensionValues": "",
                "instanceValues": ""
            },
            {
                "switchPorts": "",
                "detachSwitchPorts": "",
                "dot1QVlan": 0,
                "untagged": false,
                "fabric": "DOP-FAB-DECYO001",
                "networkName": "%s",
                "serialNumber": "FDO23270DEF",
                "vlan": 0,
                "deployment": true,
                "extensionValues": "",
                "instanceValues": ""
            }
        ],
        "networkName": "%s"
    }
]
""" % (vlanName, vlanName, vlanName, vlanName, vlanName, vlanName, vlanName, vlanName, vlanName, vlanName, vlanName, vlanName, vlanName, vlanName, vlanName, vlanName, vlanName)


uri = "/rest/top-down/fabrics/MSD001/networks/attachments"

#print(attach)
Result = DCNMPost(attach, uri, dcnmserver, token)
logger.info('Attach: %s', Result)



# Save and deploy

uri = "/rest/top-down/fabrics/MSD001/networks/deployments"

body = {
    "networkNames": vlanName
}

body = json.dumps(body)

Result = DCNMPost2(body, uri, dcnmserver, token)
logger.info('Save and Deploy: %s', Result.status)
logger.info('Save and Deploy: %s', Result.reason)