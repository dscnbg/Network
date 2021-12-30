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
vrfliste = []

# Get Token
token = getRestToken(auth.username, auth.password, auth.serverip)

networks = DCNMget(uri, auth.serverip, token)
uri2 = "/rest/top-down/fabrics/MSD001/vrfs"
dcnmvrf = DCNMget(uri2, auth.serverip, token)
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


IPAMvlans = ipam.get('/vlan/', {
    'filter_by': 'domainId',
    'filter_value': 3,
  })

#{'vlanId': '2230', 'domainId': '3', 'name': 'DOP-LAB-DOP-INTERN', 'number': '844', 'description': None, 
# 'editDate': None, 'customer_id': None, 'custom_vni': '1', 'custom_CB3': '1', 'custom_L3': '0', 'custom_VRF': None}
#
# Aus DCNM holen und in Class Object verwandeln

for dvrf in dcnmvrf:
    decodedvrf = json.loads(dvrf['vrfTemplateConfig'])
    ivrf = None
    ivrf = Cb3VRF(decodedvrf['vrfVlanId'], dvrf['vrfName'], False, 0, dvrf['vrfId'] , True)
    

    for ipamvl in IPAMvlans:
        if (decodedvrf['vrfVlanId'] == ipamvl['number']):
            ivrf.setvlanIPAMName(ipamvl['name'])
            ivrf.setIPAMid(ipamvl['vlanId'])
            ivrf.ExistsInIPAM = True

    vrfliste.append(ivrf)
counter = 1
for lvrf in vrfliste:
    print("{0} of {1}: {2}".format(counter, len(vrfliste), lvrf))
    counter = counter + 1
    ipamuri = "/vlan/" + lvrf.IPAMid
    IPAMvlans = ipam.patch(ipamuri, {
            'name': lvrf.vlanIPAMName,
            'custom_vni': lvrf.vlanVNI,
            'custom_VRF': lvrf.vrfName,
            'custom_CB3': '1',
            'custom_L3': '0',
            'description': lvrf.vrfName,
            'custom_VRF-VLAN': '1'
    })

