from phpipam_client import PhpIpamClient, GET, PATCH, POST
import json

from functions import getRestToken
from functions import DCNMPost
from functions import DCNMPost2
from functions import DCNMget

from functions import Cb3Vlan

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Array um die Netzwerke aufzunehmen
networks = []

##### Settings from settings.ini
from configparser import ConfigParser
config = ConfigParser()

config.read('C:/Temp/Git/Cisco/DCNM/settings.ini')

dcnmuser = config.get('DCNM', 'dcnmuser')
dcnmpassword = config.get('DCNM', 'dcnmpassword')
dcnmserver = config.get('DCNM', 'dcnmserver')
######

# DCNM Token abholen
token = getRestToken(dcnmuser, dcnmpassword, dcnmserver)

# ipam Konfiguration
ipam = PhpIpamClient(
    url='https://ipam.consinto.com',
    app_id='network',
    username=dcnmuser,
    ssl_verify=False,
    password=dcnmpassword,
    user_agent='myapiclient', # custom user-agent header
)

# Ipam Abfrage definieren und auslösen
IPAMvlans = ipam.get('/vlan/', {
    'filter_by': 'domainId',
    'filter_value': 3,
})

# Abgefragte Daten aus IPAM verarbeitbar machen
IPAMvlans = json.dumps(IPAMvlans)
IPAMvlans = json.loads(IPAMvlans)

count = 0

exists = True

# Durch IPAM Daten iterieren und in das Array aufnehmen
for IPAMvlan in IPAMvlans:
    if IPAMvlan['custom_CB3'] == "1":
        networks.append(Cb3Vlan(IPAMvlan['number'], IPAMvlan['name'], exists, IPAMvlan['vlanId'], IPAMvlan['custom_VRF']))
        count = count + 1
        #print(IPAMvlan['vlanId'])
        print(IPAMvlan)
        apicall = "/vlan/" + IPAMvlan['vlanId'] + '/subnets/'
        Subnet = ipam.get(apicall)
        #if Subnet != "0":
        Subnet = json.dumps(Subnet)
        Subnet = json.loads(Subnet)
        if Subnet != 0:
            for net in Subnet:
                print(net)
                #print(IPAMvlan['vlanId'])
            #print(Subnet[0]['subnet'])

print('%s Vlans marked for deployment in IPAM' % (count))

#IPAMSubnets = ipam.get('/Sections/')
#print(IPAMSubnets)


uri = "/rest/top-down/fabrics/MSD001/networks"

# DCNM Abfrage
DCNMvlans = DCNMget(uri, dcnmserver, token)

count = 0
countb = 0
for DCNMvlan in DCNMvlans:
    count = count + 1
    TemplateConfig = DCNMvlan
    TemplateConfig = json.dumps(TemplateConfig)
    TemplateConfig = json.loads(TemplateConfig)
    TemplateConfig = json.loads(TemplateConfig['networkTemplateConfig'])
    #print(TemplateConfig['vlanId'])
    for network in networks:
        if TemplateConfig['vlanId'] == network.vlanID:
            network.setCB3Deployed()
            countb = countb + 1

print('%s Vlans deployed in DCNM' % (count))
#print(countb)
for network in networks:
    if network.vlanID == "10":
        print(bool(network.CB3Deployed))