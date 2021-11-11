import http.client
import ssl
import base64
import string
import json
import argparse
import ipaddress

import logging
import logging.handlers

from ipaddress import IPv6Address
from ipaddress import IPv6Network

from functions import getRestToken, getVRF, getVRFVLAN, getNetworks
from functions import DCNMPost

##### Settings from settings.ini
from configparser import ConfigParser
config = ConfigParser()

config.read('C:/Temp/Git/Cisco/DCNM/settings.ini')

dcnmuser = config.get('DCNM', 'dcnmuser')
dcnmpassword = config.get('DCNM', 'dcnmpassword')
dcnmserver = config.get('DCNM', 'dcnmserver')
######
#
# Prüft IPAM und gibt fehlende Netze zurück
#
######

# Get Token
token = getRestToken(dcnmuser, dcnmpassword, dcnmserver)

networks = getNetworks(dcnmserver, token)

for network in networks:
    #print(network['networkName'], network['vrf'], network['networkTemplateConfig']['vlanId'] )
    #print(network['networkTemplateConfig'])
    decoded = json.loads(network['networkTemplateConfig'])
    print(network['networkName'], network['vrf'], decoded['vlanId'])
# Example
#{"fabric":"MSD001","networkName":"Trans-Klett-Service","displayName":"Trans-Klett-Service","networkId":30136,"networkTemplate":"Default_Network_Universal","networkExtensionTemplate":"Default_Network_Extension_Universal","networkTemplateConfig":"{\"suppressArp\":\"false\",\"secondaryGW2\":\"\",\"secondaryGW1\":\"\",\"vlanId\":\"3047\",\"gatewayIpAddress\":\"100.64.253.76/31\",\"networkName\":\"Trans-Klett-Service\",\"vlanName\":\"Trans-Klett-Service\",\"mtu\":\"\",\"rtBothAuto\":\"false\",\"isLayer2Only\":\"false\",\"intfDescription\":\"Trans-Klett-Service\",\"segmentId\":\"30136\",\"gatewayIpV6Address\":\"2a0c:ed80:0:400::c6/127\",\"dhcpServerAddr1\":\"\",\"tag\":\"12345\",\"nveId\":\"1\",\"vrfName\":\"Service\"}","vrf":"Service","tenantName":"","serviceNetworkTemplate":null,"source":null,"interfaceGroups":null,"networkStatus":"DEPLOYED"}
#