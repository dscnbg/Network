import http.client
import ssl
import base64
import string
import json
import argparse

from functions import getRestToken
from functions import getVRFVLAN
from functions import getVRF

##### Settings from settings.ini
from configparser import ConfigParser
config = ConfigParser()

config.read('C:/Temp/Git/Cisco/DCNM/settings.ini')

dcnmuser = config.get('DCNM', 'dcnmuser')
dcnmpassword = config.get('DCNM', 'dcnmpassword')
dcnmserver = config.get('DCNM', 'dcnmserver')
######

parser = argparse.ArgumentParser(description='DCNM Argument Parser')
#parser.add_argument("--a", default=1, type=int, help="This is the 'a' variable")
parser.add_argument("--name", required=False, type=str, help="VRF Name")
#parser.add_argument("--fabric", default="all", type=str, help="Fabric Scope, defaults to all")
args = parser.parse_args()

vrfname = args.name


# Get Token
token = getRestToken(dcnmuser, dcnmpassword, dcnmserver)

# Get VLAN ID for next VRF
vlan = getVRFVLAN(dcnmserver, token)
#print(vlan)

# get Maximum used VNI for next VRF
# DCNM kann das mit einem nicht dokumentierten API POST call... :-\
vrf = getVRF(dcnmserver, token)
y = 0
for x in vrf:
    z = x['vrfId'] 
    if z > y:
        y = z

y += 1

#print(y)

uri = "/rest/top-down/fabrics/MSD001/vrfs"

#vrfdata = {
#    "fabric": "MSD001",
#    "vrfName": "TestName",
#    "vrfId": "50015",
#    "vrfTemplate": "Default_VRF_Universal",
#    "vrfTemplateConfig": "{\"vrfVlanName\":\"TestVLAN\",\"vrfIntfDescription\":\"TestInterface\",\"vrfDescription\":\"TestVrfDesc\",\"ipv6LinkLocalFlag\":true,\"mtu\":\"9216\",\"tag\":\"12345\",\"vrfRouteMap\":\"FABRIC-RMAP-REDIST-SUBNET\",\"maxBgpPaths\":\"1\",\"maxIbgpPaths\":\"2\",\"vrfSegmentId\":\"50015\",\"vrfName\":\"TestName\",\"vrfVlanId\":\"2015\",\"nveId\":1,\"asn\":\"null\"}",
#    "vrfExtensionTemplate": "Default_VRF_Extension_Universal",
#    "source": null,
#    "serviceVrfTemplate": null
#}

#print(vrfdata)