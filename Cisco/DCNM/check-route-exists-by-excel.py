from phpipam_client import PhpIpamClient, GET, PATCH, POST
import json

import logging
import logging.handlers

import argparse

import pandas
import xlrd

from ipaddress import IPv4Interface
from ipaddress import IPv6Interface

from ipaddress import ip_network
from ipaddress import IPv6Network

from ipaddress import ip_address
from ipaddress import IPv6Address

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

logger = logging.getLogger()
logging.basicConfig(filename="spielwiese.log", filemode='a', format='%(asctime)s.%(msecs)03d %(levelname)s - %(funcName)s: %(message)s',  datefmt='%Y-%m-%d %H:%M:%S')
logger.setLevel(logging.DEBUG)

##### Settings from settings.ini
from configparser import ConfigParser
config = ConfigParser()

config.read('C:/Temp/Git/Cisco/DCNM/settings.ini')

dcnmuser = config.get('DCNM', 'dcnmuser')
dcnmpassword = config.get('DCNM', 'dcnmpassword')
dcnmserver = config.get('DCNM', 'dcnmserver')

url = config.get('IPAM', 'url')

routesv4 = []
routesv6 = []

ipv4data = pandas.read_excel('C:/Temp/Git/Cisco/DCNM/routes.xlsx', sheet_name='IPv4')

max = len(ipv4data.index)
for x in range(0, max):
    #print(ipv4data.iloc[x])
    routesv4.append(v4Route(x, ipv4data['IP_PREFIX'][x], ipv4data['NEXT_HOP_IP'][x], ipv4data['VRF_NAME'][x], ipv4data['RNAME'][x], ipv4data['TAG'][x]))

ipv6data = pandas.read_excel('C:/Temp/Git/Cisco/DCNM/routes.xlsx', sheet_name='IPv6')

max = len(ipv6data.index)
for x in range(0, max):
    #print(ipv4data.iloc[x])
    routesv6.append(v6Route(x, ipv6data['IP_PREFIX'][x], ipv6data['NEXT_HOP_IP'][x], ipv6data['VRF_NAME'][x], ipv6data['RNAME'][x], ipv6data['TAG'][x]))

switches = []

ipam = PhpIpamClient(
    url='https://ipam.consinto.com',
    app_id='network',
    username=dcnmuser,
    ssl_verify=False,
    password=dcnmpassword,
    user_agent='myapiclient', # custom user-agent header
)

# Alle VLANs aus dem IPAM holen
FabIXN = ipam.get('/devices/', {
    'filter_by': 'custom_Fabric',
    'filter_value': 'DOP-FAB-DEIXN001',
})
FabCYO = ipam.get('/devices/', {
    'filter_by': 'custom_Fabric',
    'filter_value': 'DOP-FAB-DECYO001',
})
# Array um die Switche aufzunehmen
FabIXN = json.dumps(FabIXN)
FabIXN = json.loads(FabIXN)
for switch in FabIXN:
    switches.append(FabricSwitch(switch['hostname'], switch['custom_Serial']))

for switch in FabCYO:
    switches.append(FabricSwitch(switch['hostname'], switch['custom_Serial']))

# In jeden Switch rein, und die Route Templates einfügen

# DCNM Token abholen
token = getRestToken(dcnmuser, dcnmpassword, dcnmserver)

#for switch in switches:
#    print(switch.SwitchName)

for switch in switches:
    #print(type(routesv4))
    #b = routesv4.copy()
    switch.addRoutev4(routesv4)
    switch.addRoutev6(routesv6)


for fabswitch in switches:
    uri = "/rest/control/policies/switches?serialNumber=" + fabswitch.Serial
    DCNMPolicies = DCNMget(uri, dcnmserver, token)
    DCNMPolicies = json.dumps(DCNMPolicies)
    DCNMPolicies = json.loads(DCNMPolicies)
    #print(fabswitch.SwitchName)
    logger.info('Switch: %s', fabswitch.SwitchName)
    for Policy in DCNMPolicies:
        if Policy['templateName'] == "vrf_static_route":
            #print(Policy['nvPairs']['IP_PREFIX'])
            currentPrefix = ip_network(Policy['nvPairs']['IP_PREFIX'])
            for route in fabswitch.Routev4:
                if (currentPrefix.compressed == route.Prefix) and (route.exists == False):
                    route.setExists()
                    #logstring = Policy['serialNumber'] + " " + Policy['policyId'] + " " + Policy['nvPairs']['IP_PREFIX']
                    #logger.info('Pol: %s', logstring)
                    continue
                if route.Prefix == "0.0.0.0/0":
                    route.setIgnore()
                    continue
            #print(Policy['nvPairs']['IP_PREFIX'])
        elif Policy['templateName'] == "dop_static_named_v6":
            #print(Policy['nvPairs'])
            currentPrefix = IPv6Network(Policy['nvPairs']['IPV6_PREFIX'])
            for route in fabswitch.Routev6:
                if (currentPrefix.compressed == route.Prefix) and (route.exists == False):
                    route.setExists()
                    continue
                if route.Prefix == "::/0":
                    route.setIgnore()
                    continue

print("Checking IPv4")
for fabswitch in switches:
    print(fabswitch.SwitchName)
    for route in fabswitch.Routev4:
        #print(routeX.Prefix + " " + routeX.vrf)
        if((route.exists) == False) and ((route.ignore) != True) :
            print("Prefix does not exist:")
            print(route.Prefix)
 
print("Checking IPv6")
for fabswitch in switches:
    print(fabswitch.SwitchName)
    for route in fabswitch.Routev6:
        #print(routeX.Prefix + " " + routeX.vrf)
        if((route.exists) == False) and ((route.ignore) != True) :
            print("Prefix does not exist:")
            print(route.Prefix)
                

"""

for r6 in routesv6:
    print(" python c:/Temp/Git/Cisco/DCNM/new-route6.py --v " + str(r6.vrf) + " --p " + str(r6.Prefix) + " --n " + str(r6.NextHop) + " --r " + r6.desc + " --t " + str(r6.tag))


for r6 in routesv4:
    print(" python c:/Temp/Git/Cisco/DCNM/new-route.py --v " + str(r6.vrf) + " --p " + str(r6.Prefix) + " --n " + str(r6.NextHop) + " --r " + r6.desc + " --t " + str(r6.tag))
"""