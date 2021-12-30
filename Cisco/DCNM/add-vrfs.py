import http.client
from os import truncate
import ssl
import base64
import string
import json
import argparse
import ipaddress

import sys

import logging
import logging.handlers

from phpipam_client import PhpIpamClient, GET, PATCH, POST

from ipaddress import ip_address
from ipaddress import ip_network

from functions import getRestToken
from functions import DCNMPost, DCNMget, MinimalVrf
from functions import DCNMPost2, FabricSwitch, MinimalNet
from functions import returnVRF, IPAMSettings, IPAMSetup
from functions import DCNMAuth, AuthenticateDCNM

##### Settings from settings.ini
auth = AuthenticateDCNM()

# Get Token
token = getRestToken(auth.username, auth.password, auth.serverip)

dcnmserver = auth.serverip

ipamsettings = IPAMSetup()

ipam = PhpIpamClient(
      url= ipamsettings.url,
      app_id='network',
      username= ipamsettings.ipamuser,
      ssl_verify=False,
      password= ipamsettings.ipampassword,
      user_agent='myapiclient', # custom user-agent header
)
######

CBLACK  = '\33[30m'
CRED    = '\33[31m'
CGREEN  = '\33[32m'
CYELLOW = '\33[33m'
CBLUE   = '\33[34m'
CVIOLET = '\33[35m'
CBEIGE  = '\33[36m'
CWHITE  = '\33[37m'
CEND = '\033[0m'

#print(CRED + "Error, does not compute!" + CEND)

uri = "/rest/top-down/fabrics/MSD001/vrfs"

logger = logging.getLogger()
logging.basicConfig(filename="add-vrfs.log", filemode='a', format='%(asctime)s.%(msecs)03d %(levelname)s - %(funcName)s: %(message)s',  datefmt='%Y-%m-%d %H:%M:%S')
logger.setLevel(logging.INFO)
#logger.debug("This is a debug message")
#logger.info("For your info")
#logger.warning("This is a warning message")
#logger.error("This is an error message")
#logger.critical("This is a critical message")


parser = argparse.ArgumentParser(description='DCNM Add Multple existing VRFs to multiple Switches by name or Serial')

parser.add_argument("--v", required=True, type=str, help="VRF List 'dop_intern,service'")
parser.add_argument("--s", required=True, type=str, help="Switches by Name or Serial - 'DOP-SWL-DEIXN005,DOP-SWL-DEIXN006' or 'FDO24480Z91,FDO24480YUK'")

args = parser.parse_args()

vrfstring = args.v
switchstring = args.s

logger.info("+++++++++++++++++++++++++NEW+++++++++++++++++++++++++++++")
logger.info('Settings %s', args)

# Switche aufloesen
vrflist = vrfstring.split(",")
switchsplit = switchstring.split(",")

switchlist = []

# wir holen uns hostname, serial und fabric aus dem ipam

for switch in switchsplit:
    if "DOP" in switch:
        IPAMDevices = ipam.get('/devices/',  {
        'filter_by': 'hostname',
        'filter_value': switch,
        })
        switchlist.append(FabricSwitch(IPAMDevices[0]['hostname'], IPAMDevices[0]['custom_Serial'], IPAMDevices[0]['custom_Fabric']))
        logger.info('Switch %s', IPAMDevices[0]['hostname'])
    else:
        IPAMDevices = ipam.get('/devices/',  {
        'filter_by': 'custom_Serial',
        'filter_value': switch,
        })
        switchlist.append(FabricSwitch(IPAMDevices[0]['hostname'], IPAMDevices[0]['custom_Serial'], IPAMDevices[0]['custom_Fabric']))
        logger.info('Switch %s', IPAMDevices[0]['hostname'])

uri = "/rest/top-down/fabrics/MSD001/vrfs"
networks = DCNMget(uri, auth.serverip, token)

vrfliste = []

# wir holen uns vlan id, vlan name und vrf name aus dem dcnm

for vrf in vrflist:
    for net in networks:
        template = json.loads(net['vrfTemplateConfig'])
        if vrf.upper() == template['vrfVlanName'].upper():
            vrfliste.append(MinimalVrf(template['vrfVlanId'], template['vrfSegmentId'], template['vrfVlanName']))
            logger.info("VRF {0} {1} {2}".format(template['vrfVlanId'], template['vrfSegmentId'],  template['vrfVlanName']))


# ist das vrf auf dem switch? wir brauchen eine unique list an vrf und fabrics
uniquevrf = []

for network in vrfliste:
    uniquevrf.append(network.vrfName)

uniquevrf = list(set(uniquevrf))

uniquefabric = []

for switchobj in switchlist:
    uniquefabric.append(switchobj.Fabric)

uniquefabric = list(set(uniquefabric))

# wir haben eine unique liste an vrf und eine unique liste der fabrics. jetzt koennen wir den dcnm abfragen welche switche der fabric die vrf attachet haben
ende = False
for unin in uniquevrf:
    for unif in uniquefabric:
        uri2 = "/rest/top-down/fabrics/{0}/vrfs/attachments?vrf-names={1}".format(unif, unin)
        attachedvrf = DCNMget(uri2, auth.serverip, token)
        for attached in attachedvrf:
            for i in attached['lanAttachList']:
                for sw in switchlist:
                    if i['switchName'] == sw.SwitchName:
                        if i['isLanAttached'] == True:
                            print(CRED + "VRF {0} is attached to Switch {1}".format(unin, sw.SwitchName) + CEND)
                            logger.info("VRF {0} is ALREADY attached to Switch {1} Serial {2} Fabric {3}".format(unin, sw.SwitchName, sw.Serial, sw.Fabric))
                            ende = True
                        else:
                            print(CGREEN + "VRF {0} is NOT attached to Switch {1} Serial {2} Fabric {3}".format(unin, sw.SwitchName, sw.Serial, sw.Fabric) + CEND)
                            

if ende == True:
    print("Script terminated. VRFs already attached. See log for details.")
    logger.info("Script terminated.")
    sys.exit()


# Wenn das Skript bis hier noch laeuft, dann koennen wir die Netze an die switche attachen

beginning = """
[
    {
        "lanAttachList": [
"""


for network in vrfliste:
    counter = 0
    poststring = beginning
    for sw in switchlist:
        counter = counter + 1
        block = ""
        block = """{
                "fabric": "%s", 
                "vrfName": "%s", 
                "serialNumber": "%s", 
                "vlan": 0, 
                "deployment": true, 
                "extensionValues": "", 
                "instanceValues": "" 
            }
            """ % (sw.Fabric, network.vrfName, sw.Serial)
        poststring = poststring + block
        if counter < int(len(switchlist)):
            poststring = poststring + ","
    endestring = """],
        "vrfName": "%s"
    }
]
    """ % (network.vrfName)
    poststring = poststring + endestring
    #logger.info('Poststring: %s', poststring)
    uri = "/rest/top-down/fabrics/MSD001/vrfs/attachments"
    print(CGREEN + "Attaching Network {0} to Switches".format(network.vrfName) + CEND)
    Result = DCNMPost(poststring, uri, dcnmserver, token)
    logger.info('Attach: %s', Result)
