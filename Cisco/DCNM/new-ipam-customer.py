from phpipam_client import PhpIpamClient, GET, PATCH, POST
import json

import logging
import logging.handlers

import argparse

from functions import Cb3Vlan

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Logging
logger = logging.getLogger()
logging.basicConfig(filename="new-ipam-customer.log", filemode='a', format='%(asctime)s.%(msecs)03d %(levelname)s - %(funcName)s: %(message)s',  datefmt='%Y-%m-%d %H:%M:%S')
logger.setLevel(logging.INFO)

# Argument Parser aufruf
parser = argparse.ArgumentParser(description='DCNM IPAM Customer')
parser.add_argument("--n", required=True, type=str, help="Kundenbezeichnung z. B. customer009")
parser.add_argument("--m", required=True, type=str, help="Kundenname z. B. Vibalogics")
args = parser.parse_args()
customerID = args.n
customerName = args.m

logger.info('Settings %s', args)

# Array um die Netzwerke aufzunehmen
networks = []

##### Settings from settings.ini
from configparser import ConfigParser
config = ConfigParser()

config.read('C:/Temp/Git/Cisco/DCNM/settings.ini')

dcnmuser = config.get('DCNM', 'dcnmuser')
dcnmpassword = config.get('DCNM', 'dcnmpassword')
dcnmserver = config.get('DCNM', 'dcnmserver')

ipamuser = config.get('IPAM', 'ipamuser')
ipampassword = config.get('IPAM', 'ipampassword')
ipamserver = config.get('IPAM', 'url')

######

servicename = customerName + '-Transfer-Service'
externname = customerName + '-Transfer-Extern' 
# DCNM Token abholen
# token = getRestToken(dcnmuser, dcnmpassword, dcnmserver)

# ipam Konfiguration
ipam = PhpIpamClient(
    url='https://ipam.consinto.com',
    app_id='network',
    username=ipamuser,
    ssl_verify=False,
    password=ipampassword,
    user_agent='myapiclient', # custom user-agent header
)

# BLUE
# Blue braucht ein VLAN im Bereich 3000 - 3499

# Alle VLANs aus dem IPAM holen
IPAMvlans = ipam.get('/vlan/', {
    'filter_by': 'domainId',
    'filter_value': 3,
})

# Liste bauen der VLAN Nummern
for IPAMVlan in IPAMvlans:
    networks.append(int(IPAMVlan['number']))


# Sortieren
networks = sorted(networks)

bluevlan = 0

# Lücke finden
last = 3000
for network in networks:
    if network > 3000 and network < 3500:
        if (last + 1) == network:
            last = network
        else:
            if (last + 1) != network:
                bluevlan = last + 1
                break

# Lücke gefunden - neues VLAN rein ins IPAM
logger.info('Blue-VLAN %s', bluevlan)
print("Blue VLAN: ", bluevlan)
namestring = customerID + '_' + customerName
IPAMvlans = ipam.post('/vlan/', {
    'domainId': 3,
    'name': namestring,
    'number': bluevlan,
    'description': customerName,
    'custom_CB3': 1,
    'custom_L3': 1,
    'custom_VRF': 'Service'
})

# Das VLAN wieder suchen weil wir die ID nicht als return Wert bekommen - alle VLANs abfragen
IPAMvlans = ipam.get('/vlan/', {
    'filter_by': 'domainId',
    'filter_value': 3,
})

# nach unserem VLAN suchen
for IPAMVlan in IPAMvlans:
    current = int(IPAMVlan['number'])
    if current == bluevlan:
        blueIpamId = IPAMVlan['vlanId']
        #print(IPAMVlan)



# RED
# Red braucht ein VLAN im Bereich 3500 - 3600
redvlan = 0

last = 3500
for networkr in networks:
    if networkr > 3500 and networkr < 3600:
        if (last + 1) == networkr:
            last = networkr
        else:
            if (last + 1) != networkr:
                redvlan = last + 1
                break

logger.info('Red-VLAN %s', redvlan)
print("Red VLAN: ", redvlan)
namestring = customerID + '_' + customerName
IPAMvlans = ipam.post('/vlan/', {
    'domainId': 3,
    'name': namestring,
    'number': redvlan,
    'description': customerName,
    'custom_CB3': 1,
    'custom_L3': 1,
    'custom_VRF': 'Extern'
})
# Wieder die VLANs abholen
IPAMvlans = ipam.get('/vlan/', {
    'filter_by': 'domainId',
    'filter_value': 3,
})
# nach unserem VLAN suchen
for IPAMVlan in IPAMvlans:
    current = int(IPAMVlan['number'])
    if current == redvlan:
        redIpamId = IPAMVlan['vlanId']
        #print(IPAMVlan)


###############
# Ab hier anlage Roter IP Adress Bereich
#
# IPv4 Subnet Verknüpfung - das ist das Container Subnet für blaue Links in VRF Service

"""
'id': '921',
'sectionId' : '1'
"""
# Wir holen uns das erste freie /31 im container
IPAMsubnets = ipam.get('/subnets/921/first_subnet/31/')
redv4 = IPAMsubnets
logger.info('Red IPv4 Subnet %s', IPAMsubnets)
subnet = IPAMsubnets.split("/")
#print(subnet)


# Mit dieser Info erstellen wir dieses Netz
IPAMvlans = ipam.post('/subnets/', {
    'subnet': subnet[0],
    'mask': subnet[1],
    'sectionId': '1',
    'description': namestring,
    'masterSubnetId': 921,
    'vlanId': redIpamId
})

# Wir holen uns die ID des Subnetzes ab
searchstring = '/subnets/cidr/' + IPAMsubnets + '/'
redv4Info = ipam.get(searchstring, {
    'filter_by': 'sectionId',
    'filter_value': 1,
})

#print(bluev4Info)
redv4Info = json.dumps(redv4Info[0])
redv4Info = json.loads(redv4Info)
redId = redv4Info['id']
logger.info('IPv4 RED ID %s', redId)

urlstring = 'https://ipam.consinto.com/index.php?page=subnets&section=1&subnetId=' + redId
logger.info('URL: %s', urlstring)
print(urlstring)
###############
# Ab hier anlage Blauer IP Adress Bereich
#
# IPv4 Subnet Verknüpfung - das ist das Container Subnet für blaue Links in VRF Service

"""
'id': '138', 'subnet': '100.64.253.0', 'mask': '24', 'sectionId': '1', 'description': 'Transfer VRF Service', 
'linked_subnet': None, 'firewallAddressObject': None, 'vrfId': '0', 'masterSubnetId': '137', 'allowRequests': None,
 'vlanId': '0', 'showName': '0', 'device': '0', 'permissions': '{"2":"2","3":"1","4":"3"}', 'pingSubnet': '0',
  'discoverSubnet': '0', 'resolveDNS': '0', 'DNSrecursive': '0', 'DNSrecords': '0', 'nameserverId': '0',
   'scanAgent': '0', 'customer_id': None, 'isFolder': '0', 'isFull': '0', 'tag': '2', 'threshold': '0', 'location': '0',
    'editDate': '2020-04-23 08:08:14', 'lastScan': None, 'lastDiscovery': None, 'custom_vdom': None, 'custom_active': '1',
     'calculation': {'Type': 'IPv4', 'IP address': '/', 'Network': '100.64.253.0', 'Broadcast': '100.64.253.255', 'Subnet bitmask': '24',
      'Subnet netmask': '255.255.255.0', 'Subnet wildcard': '0.0.0.255', 'Min host IP': '100.64.253.1', 'Max host IP': '100.64.253.254',
       'Number of hosts': '254', 'Subnet Class': False}}
"""

# Wir holen uns das erste freie /31 im container
IPAMsubnets = ipam.get('/subnets/138/first_subnet/31/')
logger.info('Blue IPv4 Subnet %s', IPAMsubnets)
subnet = IPAMsubnets.split("/")
#print(subnet)

# Mit dieser Info erstellen wir dieses Netz
IPAMvlans = ipam.post('/subnets/', {
    'subnet': subnet[0],
    'mask': subnet[1],
    'sectionId': '1',
    'description': namestring,
    'masterSubnetId': 138,
    'vlanId': blueIpamId
})
# Wir holen uns die ID des Subnetzes ab
searchstring = '/subnets/cidr/' + IPAMsubnets + '/'
bluev4Info = ipam.get(searchstring, {
    'filter_by': 'sectionId',
    'filter_value': 1,
})
#print(bluev4Info)
bluev4Info = json.dumps(bluev4Info[0])
bluev4Info = json.loads(bluev4Info)
blueId = bluev4Info['id']
logger.info('IPv4 ID %s', blueId)

urlstring = 'https://ipam.consinto.com/index.php?page=subnets&section=1&subnetId=' + blueId
logger.info('URL: %s', urlstring)
print(urlstring)

###########
# Ab hier RED IPv6
#
# IPv6 Subnet Verknüpfen - das ist das Container Subnet für blaue Links in VRF Service

"""
'section'='2',
'subnetId'='915'
"""
# Wir suchen das erste freie /64
IPAMv6subnets = ipam.get('/subnets/915/first_subnet/64/')
redv6 = IPAMv6subnets
logger.info('Blue IPv6 Subnet %s', IPAMv6subnets)
v6subnet = IPAMv6subnets.split("/")
# Das neue Netz wird angelegt
IPAMvlans = ipam.post('/subnets/915/first_subnet/64/', {
    'description': namestring,
    'vlanId': redIpamId
})
searchstring = '/subnets/cidr/' + IPAMv6subnets + '/'
redv6Info = ipam.get(searchstring, {
    'filter_by': 'sectionId',
    'filter_value': 2,
})
redv6Info = json.dumps(redv6Info[0])
redv6Info = json.loads(redv6Info)
redv6Id = redv6Info['id']
logger.info('Red IPv6 ID %s', redv6Id)
urlstring = 'https://ipam.consinto.com/index.php?page=subnets&section=2&subnetId=' + redv6Id
logger.info('URL: %s', urlstring)
print(urlstring)

###########
# Ab hier Blue IPv6
#
# IPv6 Subnet Verknüpfen - das ist das Container Subnet für blaue Links in VRF Service

"""
'id': '13', 'subnet': '2a0c:ed80:0:400::', 'mask': '64', 'sectionId': '2', 
'description': 'Transfer Netze', 'linked_subnet': None, 'firewallAddressObject': None, 
'vrfId': '0', 'masterSubnetId': '12', 'allowRequests': '0', 'vlanId': '0', 'showName': '0', 
'device': '0', 'permissions': '{"3":"1","2":"2","4":"3"}', 'pingSubnet': '0', 'discoverSubnet': '0', 'resolveDNS': '0', 'DNSrecursive': '0', 'DNSrecords': '0', 'nameserverId': '0', 'scanAgent': '0', 'customer_id': None, 'isFolder': '0', 'isFull': '0', 'tag': '2', 'threshold': '0', 'location': '0', 'editDate': '2020-08-27 09:48:36', 'lastScan': None, 'lastDiscovery': 
None, 'custom_vdom': None, 'custom_active': '1', 'calculation': {'Type': 'IPv6', 'Host address': '/', 
'Host address (uncompressed)': '/', 'Subnet prefix': '2a0c:ed80:0:400::/64', 'Prefix length': '64', 
'Subnet Reverse DNS': '0.0.4.0.0.0.0.0.0.8.d.e.c.0.a.2.ip6.arpa', 'Min host IP': '2a0c:ed80:0:400:0:0:0:0', 
'Max host IP': '2a0c:ed80:0:400:ffff:ffff:ffff:ffff', 'Number of hosts': '18446744073709551616', 'Address 
type': 'NET_IPV6'}}
"""
# Wir suchen das erste freie /127
IPAMv6subnets = ipam.get('/subnets/13/first_subnet/127/')
logger.info('Blue IPv6 Subnet %s', IPAMv6subnets)
v6subnet = IPAMv6subnets.split("/")
# Das neue Netz wird angelegt
IPAMvlans = ipam.post('/subnets/13/first_subnet/127/', {
    'description': namestring,
    'vlanId': blueIpamId
})
# Wir suchen uns die ID des Netzwerks
searchstring = '/subnets/cidr/' + IPAMv6subnets + '/'
bluev6Info = ipam.get(searchstring, {
    'filter_by': 'sectionId',
    'filter_value': 2,
})
#print(bluev6Info)
bluev6Info = json.dumps(bluev6Info[0])
bluev6Info = json.loads(bluev6Info)
bluev6Id = bluev6Info['id']
logger.info('IPv6 ID %s', bluev6Id)
urlstring = 'https://ipam.consinto.com/index.php?page=subnets&section=2&subnetId=' + bluev6Id
logger.info('URL: %s', urlstring)
print(urlstring)

#################
# Eintragen der Host Adressen "AnycastGateway" und Firewall in die Subnetze
# Device Anycast-Gateway
"""
[{'id': '83', 'hostname': 'Fabric-Anycast', 'ip': None, 'type': '9', 
'description': None, 'sections': '1;2;4;5', 'snmp_community': None, 
'snmp_version': '0', 'snmp_port': '161', 'snmp_timeout': '1000', 
'snmp_queries': None, 'snmp_v3_sec_level': 'none', 'snmp_v3_auth_protocol': 'none', 
'snmp_v3_auth_pass': None, 'snmp_v3_priv_protocol': 'none', 'snmp_v3_priv_pass': None, 
'snmp_v3_ctx_name': None, 'snmp_v3_ctx_engine_id': None, 'rack': '0', 'rack_start': '0', 'rack_size': '0', 
'location': '0', 'editDate': None, 'custom_Serial': None, 'custom_Fabric': None}]
"""

# Fortigate Customer Interface Device
"""
[{'id': '84', 'hostname': 'Fortigate-Customer-Interface', 'ip': None, 'type': '9', 'description': None, 
'sections': '1;2;4;5', 'snmp_community': None, 'snmp_version': '0', 'snmp_port': '161', 'snmp_timeout': '1000', 
'snmp_queries': None, 'snmp_v3_sec_level': 'none', 'snmp_v3_auth_protocol': 'none', 
'snmp_v3_auth_pass': None, 'snmp_v3_priv_protocol': 'none', 'snmp_v3_priv_pass': None, 
'snmp_v3_ctx_name': None, 'snmp_v3_ctx_engine_id': None, 'rack': '0', 'rack_start': '0', 
'rack_size': '0', 'location': '0', 'editDate': '2020-11-25 07:43:28', 'custom_Serial': None, 'custom_Fabric': None}]
"""
########## BLUE
# IPv4 Host eintragen
searchstring = '/addresses/first_free/' + blueId + '/'
IPAMvlans = ipam.post(searchstring, {
    'description': 'AnycastGateway',
    'hostname': 'AnycastGateway',
    'deviceId': 83
})
searchstring = '/addresses/first_free/' + blueId + '/'
IPAMvlans = ipam.post(searchstring, {
    'description': 'Fortigate',
    'hostname': 'Fortigate',
    'deviceId': 84
})
# IPv6 Host eintragen
searchstring = '/addresses/first_free/' + bluev6Id + '/'
IPAMvlans = ipam.post(searchstring, {
    'description': 'AnycastGateway',
    'hostname': 'AnycastGateway',
    'deviceId': 83
})
searchstring = '/addresses/first_free/' + bluev6Id + '/'
IPAMvlans = ipam.post(searchstring, {
    'description': 'Fortigate',
    'hostname': 'Fortigate',
    'deviceId': 84
})
############# RED
# IPv4 Host eintragen
searchstring = '/addresses/first_free/' + redId + '/'
IPAMvlans = ipam.post(searchstring, {
    'description': 'AnycastGateway',
    'hostname': 'AnycastGateway',
    'deviceId': 83
})
searchstring = '/addresses/first_free/' + redId + '/'
IPAMvlans = ipam.post(searchstring, {
    'description': 'Fortigate',
    'hostname': 'Fortigate',
    'deviceId': 84
})
# IPv6 Host eintragen
searchstring = '/addresses/first_free/' + redv6Id + '/'
IPAMvlans = ipam.post(searchstring, {
    'description': 'NA',
    'hostname': 'NA'
})
IPAMvlans = ipam.post(searchstring, {
    'description': 'AnycastGateway',
    'hostname': 'AnycastGateway',
    'deviceId': 83
})
searchstring = '/addresses/first_free/' + redv6Id + '/'
IPAMvlans = ipam.post(searchstring, {
    'description': 'Fortigate',
    'hostname': 'Fortigate',
    'deviceId': 84
})
# Output ist die Konfig Zeile mit der das DCNM Script angesteuert werden kann
outputstring = "& python c:/Temp/Git/Cisco/DCNM/new-l3vlan.py --v Service --i %s --n %s --a %s --b %s" % (bluevlan, servicename, IPAMsubnets, IPAMv6subnets)
print(outputstring)
logger.info('DCNM: %s', outputstring)
outputstring = "& python c:/Temp/Git/Cisco/DCNM/new-l3vlan.py --v Extern --i %s --n %s --a %s --b %s" % (redvlan, externname, redv4, redv6)
print(outputstring)
logger.info('DCNM: %s', outputstring)

# Blau ist fertig
# Rot ist fertig