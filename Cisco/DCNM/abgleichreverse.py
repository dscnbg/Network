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
from functions import DCNMPost2, IPAMSettings, IPAMSetup
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

ipamsettings = IPAMSetup()

ipam = PhpIpamClient(
      url= ipamsettings.url,
      app_id='network',
      username= ipamsettings.ipamuser,
      ssl_verify=False,
      password= ipamsettings.ipampassword,
      user_agent='myapiclient', # custom user-agent header
)
#IPAMvlans = ipam.patch('/vlan/2503', {
#    'name': 'FID_SDWorx_HB',
#    'custom_vni': '12345',
#    'custom_VRF': 'Boller',
#    'custom_CB3': '1',
#    'custom_L3': '1',
#})

#{'id': '30', 'hostname': 'DOP-SWL-DECYO004', 'ip': '10.110.126.16', 'type': '1', 'description': None, 'sections': '1;2', 
# 'snmp_community': None, 'snmp_version': '0', 'snmp_port': '161', 'snmp_timeout': '1000', 'snmp_queries': None, 'snmp_v3_sec_level': 'none', 
# 'snmp_v3_auth_protocol': 'none', 'snmp_v3_auth_pass': None, 'snmp_v3_priv_protocol': 'none', 'snmp_v3_priv_pass': None, 'snmp_v3_ctx_name': None, 
# 'snmp_v3_ctx_engine_id': None, 'rack': '8', 'rack_start': '1', 'rack_size': '1', 'location': '1', 'editDate': '2021-12-20 08:47:06', 
# 'custom_Serial': 'FDO23270DEW', 'custom_Fabric': 'DOP-FAB-DECYO001', 'custom_Switch-Role': 'Shared-Leaf'

IPAMDevices = ipam.get('/devices/',  {
    'filter_by': 'hostname',
    'filter_value': "DOP-SWL-DECYO004",
  })

print(IPAMDevices)