import http.client
import ssl
import base64
import string
import json
import argparse
import ipaddress
import os
import sys

import logging
import logging.handlers

from ipaddress import ip_address
from ipaddress import ip_network
from phpipam_client import PhpIpamClient, GET, PATCH, POST
from functions import getRestToken
from functions import DCNMPost
from functions import DCNMPost2
from functions import returnVRF, DCNMget, Cb3Vlan, DCNMAuth, AuthenticateDCNM, Cb3VRF

##### Settings from settings.ini

auth = AuthenticateDCNM()

######

uri = "/rest/top-down/fabrics/MSD001/networks"

logger = logging.getLogger()
logging.basicConfig(filename="abgleich.log", filemode='a', format='%(asctime)s.%(msecs)03d %(levelname)s - %(funcName)s: %(message)s',  datefmt='%Y-%m-%d %H:%M:%S')
logger.setLevel(logging.DEBUG)

netzliste = []

# Get Token
token = getRestToken(auth.username, auth.password, auth.serverip)

networks = DCNMget(uri, auth.serverip, token)

empty = ""

folder = os.path.join(os.environ['USERPROFILE'], "Script-Settings")
from configparser import ConfigParser
config = ConfigParser()
folder = folder.replace("\\","/")
folder = folder + "/settings.ini"
config.read(folder)
ipamuser = config.get('IPAM', 'ipamuser')
ipampassword = config.get('IPAM', 'ipampassword')

ipam = PhpIpamClient(
      url='https://ipam.consinto.com',
      app_id='network',
      username=ipamuser,
      ssl_verify=False,
      password=ipampassword,
      user_agent='myapiclient', # custom user-agent header
)
#IPAMvlans = ipam.patch('/vlan/2503', {
#    'name': 'FID_SDWorx_HB',
#    'custom_vni': '12345',
#    'custom_VRF': 'Boller',
#    'custom_CB3': '1',
#    'custom_L3': '1',
#})

IPAMvlans = ipam.get('/vlan/', {
    'filter_by': 'domainId',
    'filter_value': 3,
  })

#{'vlanId': '2230', 'domainId': '3', 'name': 'DOP-LAB-DOP-INTERN', 'number': '844', 'description': None, 
# 'editDate': None, 'customer_id': None, 'custom_vni': '1', 'custom_CB3': '1', 'custom_L3': '0', 'custom_VRF': None}
#
# Aus DCNM holen und in Class Object 
# Alle Netze aus DCNM sind angelegt

for net in networks:
    decoded = json.loads(net['networkTemplateConfig'])
    netz = None
    netz = Cb3Vlan(decoded['vlanId'], decoded['vlanName'], False, True, "0", decoded['vrfName'], decoded['segmentId'], True)
    
    if (decoded['gatewayIpAddress'] != empty):
        netz.setIPv4Address(decoded['gatewayIpAddress'])
    if (decoded['gatewayIpAddress'] != empty):
        netz.setIPv6Address(decoded['gatewayIpV6Address'])
    
    for ipamvl in IPAMvlans:
        if (decoded['vlanId'] == ipamvl['number']):
            #print(ipamvl)
            netz.setvlanIPAMName(ipamvl['name'])
            netz.setIPAMid(ipamvl['vlanId'])
            netz.IPAMVNI = ipamvl['custom_vni']
            netz.ExistsInIPAM = True

    netzliste.append(netz)

# Haben wir Netze im IPAM die nicht im DCNM sind?
check = False
for ipamnet in IPAMvlans:
    if (ipamnet['custom_CB3'] == "1") and (ipamnet['custom_VRF-VLAN'] != "1"):
        # ist es schon in der netzliste?
        for net in netzliste:
            if (str(net.vlanID) == ipamnet['number']):
                check = True
        if check == False:
            print(ipamnet['number'])
        check = False

#counter = 1
#for netze in netzliste:
#    print("{0} of {1}: {2}".format(counter, len(netzliste), netze))
#    counter = counter + 1
#    if (netze.CB3Layer3 == True):
#        ipamuri = "/vlan/" + netze.IPAMid
#        #print(ipamuri)
#        IPAMvlans = ipam.patch(ipamuri, {
#            'name': netze.vlanIPAMName,
#            'custom_vni': netze.vlanVNI,
#            'custom_VRF': netze.VRF,
#            'custom_CB3': '1',
#            'custom_L3': '1',
#            })
#    if (netze.CB3Layer3 == False):
#        ipamuri = "/vlan/" + netze.IPAMid
#        #print(ipamuri)
#        IPAMvlans = ipam.patch(ipamuri, {
#            'name': netze.vlanIPAMName,
#            'custom_vni': netze.vlanVNI,
#            'custom_VRF': netze.VRF,
#            'custom_CB3': '1',
#            'custom_L3': '0',
#            })
#    if (netze.vlanID == "855"):
#        ipamuri = "/vlan/" + netze.IPAMid
#        #print(ipamuri)
#        IPAMvlans = ipam.patch(ipamuri, {
#            'name': netze.vlanIPAMName,
#            'custom_vni': netze.vlanVNI,
#            'custom_VRF': netze.VRF,
#            'custom_CB3': '1',
#            'custom_L3': '0',
#            })
#for vlans in IPAMvlans:
#    print(vlans)