from phpipam_client import PhpIpamClient, GET, PATCH, POST
import json

import logging
import logging.handlers

import argparse

import pandas
import xlrd

from functions import getRestToken
from functions import DCNMPost
from functions import DCNMPost2
from functions import DCNMget
from functions import FabricSwitch
from functions import v4Route
from functions import v6Route

from functions import Cb3Vlan

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

##### Settings from settings.ini
from configparser import ConfigParser
config = ConfigParser()

config.read('C:/Temp/Git/Cisco/DCNM/settings.ini')

dcnmuser = config.get('DCNM', 'dcnmuser')
dcnmpassword = config.get('DCNM', 'dcnmpassword')
dcnmserver = config.get('DCNM', 'dcnmserver')

url = config.get('IPAM', 'url')

switches = []
routesv4 = []
routesv6 = []
ipam = PhpIpamClient(
    url='https://ipam.consinto.com',
    app_id='network',
    username=dcnmuser,
    ssl_verify=False,
    password=dcnmpassword,
    user_agent='myapiclient', # custom user-agent header
)
"""
# Alle Devices aus dem IPAM holen
FabIXN = ipam.get('/devices/', {
    'filter_by': 'custom_Fabric',
    'filter_value': 'DOP-FAB-DEIXN001',
})
FabCYO = ipam.get('/devices/', {
    'filter_by': 'custom_Fabric',
    'filter_value': 'DOP-FAB-DECYO001',
})
# Array um die Devices aufzunehmen
FabIXN = json.dumps(FabIXN)
FabIXN = json.loads(FabIXN)
for switch in FabIXN:
    switches.append(FabricSwitch(switch['hostname'], switch['custom_Serial']))

for switch in FabCYO:
    switches.append(FabricSwitch(switch['hostname'], switch['custom_Serial']))

# DCNM Token abholen
token = getRestToken(dcnmuser, dcnmpassword, dcnmserver)

for fabswitch in switches:

    uri = "/rest/control/policies/switches?serialNumber=" + fabswitch.Serial
    # DCNM Abfrage
    DCNMPolicies = DCNMget(uri, dcnmserver, token)
    DCNMPolicies = json.dumps(DCNMPolicies)
    DCNMPolicies = json.loads(DCNMPolicies)
    for Policy in DCNMPolicies:
        if Policy['templateName'] == "vrf_static_route":
            print(Policy['nvPairs'])
        elif Policy['templateName'] == "vrf_static_route_v6":
            print(Policy['nvPairs'])

"""

ipv4data = pandas.read_excel('C:/Temp/Git/Cisco/DCNM/routes.xlsx', sheet_name='IPv4')

max = len(ipv4data.index)
for x in range(1, max):
    #print(ipv4data.iloc[x])
    routesv4.append(v4Route(x, ipv4data['IP_PREFIX'][x], ipv4data['NEXT_HOP_IP'][x], ipv4data['VRF_NAME'][x], ipv4data['RNAME'][x], ipv4data['TAG'][x]))


ipv6data = pandas.read_excel('C:/Temp/Git/Cisco/DCNM/routes.xlsx', sheet_name='IPv6')

max = len(ipv6data.index)
for x in range(1, max):
    #print(ipv4data.iloc[x])
    routesv6.append(v6Route(x, ipv6data['IP_PREFIX'][x], ipv6data['NEXT_HOP_IP'][x], ipv6data['VRF_NAME'][x], ipv6data['RNAME'][x], ipv6data['TAG'][x]))

"""
location = ("C:/Temp/Git/Cisco/DCNM/routes.xlsx")
wb = xlrd.open_workbook(location)
sheet = wb.sheet_by_index(0)

maxcol = sheet.ncols
maxrow = sheet.nrows
for x in range(1, maxrow):
    print(sheet.row_values(x))
    """