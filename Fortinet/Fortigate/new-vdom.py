from phpipam_client import PhpIpamClient, GET, PATCH, POST
import json

from fortifunctions import NextFreeVlan, CreateServiceVlan, CreateOrangeSubnetv4, CreateExternVlan, CreateGreenVlan, DCNML3VLAN, FortiDefaultv4, FortiDefaultv6
from fortifunctions import CreateNewSection, CreateBlueSubnetv4, CreateBlueSubnetv6, CLIBlue, CLIOrange, NewGreenSubnet, CLIGreen, FortiRoutev4, DCNMv4Route, ForcepointNew
from fortifunctions import CreateRedSubnetv4, CreateRedSubnetv6, CLIRed, CreateOrangeSubnetv6, CreateCustomerSlash56, CreateGreenSubnetv4, FortiRoutev6, DCNMv6Route

import logging
import logging.handlers
import sys

import argparse
from configparser import ConfigParser
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

parser = argparse.ArgumentParser(description='IPAM und Fortigate Neukunden Anlage - Blau wird immer angelegt')

parser.add_argument("--c", required=True, type=str, help="customer ID z. B. customer123")
parser.add_argument("--k", required=True, type=str, help="Kunden Kürzel z. B. OFRE")
parser.add_argument("--n", required=True, type=str, help="Kunden Name ohne Leerzeichen z. B. Metrawatt")
parser.add_argument("--r", help="Rotes Interface gebraucht?", action="store_true")
parser.add_argument("--g", help="Gruenes Interface gebraucht?", action="store_true")
parser.add_argument("--o", help="rotes interface für altkunden", action="store_true")

args = parser.parse_args()

customerID = args.c
kuerzel = args.k
namelang = args.n

cfgbase = """

*********************
* Fortigate
*********************

config vdom
edit %s
config system interface
""" % (customerID)
# Ablauf:

custslash56ID = None

##############
# Section anlegen
##############

#sectionid = CreateNewSection(kuerzel, customerID)

##############
# Blaues VLAN anlegen und IPs vergeben
##############
bluevlan = NextFreeVlan(3050, 3099)
bluevlanname = customerID + "_" + namelang
bluevlanID = CreateServiceVlan(bluevlan, bluevlanname, namelang)
bluev4SubnetID = CreateBlueSubnetv4(bluevlanID, bluevlanname)
bluev6SubnetID = CreateBlueSubnetv6(bluevlanID, bluevlanname)

cfgblue = CLIBlue(bluevlanID, customerID)
cfgbase = cfgbase + cfgblue

##############
# Rotes VLAN anlegen und IPs vergeben
##############
if args.o:
    redvlan = NextFreeVlan(3500, 3600)
    redvlanname = customerID + "_" + namelang
    redvlanID = CreateExternVlan(redvlan, redvlanname, namelang)
    redv4SubnetID = CreateRedSubnetv4(redvlanID, redvlanname)
    redv6SubnetID = CreateRedSubnetv6(redvlanID, redvlanname)

    cfgred = CLIRed(redvlanID, customerID)
    cfgbase = cfgbase + cfgred

if args.r:
    redvlan = NextFreeVlan(3500, 3600)
    redvlanname = customerID + "_" + namelang
    redvlanID = CreateExternVlan(redvlan, redvlanname, namelang)
    redv4SubnetID = CreateRedSubnetv4(redvlanID, redvlanname)
    redv6SubnetID = CreateRedSubnetv6(redvlanID, redvlanname)

    cfgred = CLIRed(redvlanID, customerID)
    cfgbase = cfgbase + cfgred

    ##############
    # Orangenes VLAN anlegen und IPs anlegen - wer rot hat, der hat auch orange
    ##############
    orangevlan = NextFreeVlan(2501, 2600)
    orangevlanname = customerID + "_" + namelang
    orangevlanID = CreateExternVlan(orangevlan, orangevlanname, namelang)
    orangev4SubnetID = CreateOrangeSubnetv4(orangevlanID, orangevlanname)
    custslash56ID = CreateCustomerSlash56(orangevlanname)
    orangepublicname = orangevlanname + "_Public"
    custOrangeId = CreateOrangeSubnetv6(orangevlanID, custslash56ID, orangepublicname)
    cfgorange = CLIOrange(orangevlanID, customerID)
    cfgbase = cfgbase + cfgorange

if args.g:
    print(cfgbase)
    greenvlan = NextFreeVlan(830, 999)
    greenvlanname = customerID + "_" + namelang
    greenv6name = greenvlanname + "_Server"
    if not args.r:
        custslash56ID = CreateCustomerSlash56(greenvlanname)

    greenVlanID = CreateGreenVlan(greenvlan, greenvlanname, namelang)
    custgreenV6Id = CreateOrangeSubnetv6(greenVlanID, custslash56ID, greenv6name)
    greenoctet = NewGreenSubnet()
    print(greenoctet)
    greensubnet = CreateGreenSubnetv4(greenVlanID, greenoctet, greenvlanname)
    print(greensubnet)

    cfggreen = CLIGreen(greenVlanID, customerID)
    cfgbase = cfgbase + cfggreen

##############
# Weder gruen noch rot noch orange
# wir brauchen trotzdem ein /56
##############

if (custslash56ID == None):
    custslash56ID = CreateCustomerSlash56(bluevlanname)

##############
# DCNM scripts vorbereiten
##############


dcnmText = """*********************
* DCNM
*********************
"""

dcnmservice = DCNML3VLAN("Service", bluevlanID, customerID)
dcnmText = dcnmText + """
"""
dcnmText = dcnmText + dcnmservice
if args.r or args.o:
    dcnmextern = DCNML3VLAN("Extern", redvlanID, customerID)
    dcnmText = dcnmText + """
"""
    dcnmText = dcnmText + dcnmextern
    dcnmText = dcnmText + """
"""
# DCNM Routes

if args.r:
    routeorange = DCNMv4Route("Extern", redvlanID, orangevlanID, namelang)
    dcnmText = dcnmText + routeorange

dcnmText = dcnmText + """
"""
routeservice = DCNMv6Route("Service", bluevlanID, custslash56ID, namelang)
dcnmText = dcnmText + routeservice

##############
# Forcepoint
##############

ForcepointText = """

*********************
* Forcepoint
*********************

"""

if args.r:
    fpanlage = ForcepointNew(customerID, kuerzel, orangevlanID, custslash56ID)
    ForcepointText = ForcepointText + fpanlage

##############
# Routing Fortigate
##############

fortiroute = """
end
config router static
"""

# blue 185.213.35.0/24

serviceRoute = FortiRoutev4(bluevlanID, customerID)

fortiroute = fortiroute + serviceRoute

# red default

if args.r:
    redroute = FortiDefaultv4(redvlanID, customerID)
    fortiroute = fortiroute + redroute

endstring = """end
"""
fortiroute = fortiroute + endstring

# blue ipv6
fortiroutev6 = """
config router static6
"""

serviceroute6 = FortiRoutev6(bluevlanID, customerID)
fortiroutev6 = fortiroutev6 + serviceroute6
# red ipv6

if args.r:
    redroute6 = FortiDefaultv6(redvlanID, customerID)
    fortiroutev6 = fortiroutev6 + redroute6

fortiroutev6 = fortiroutev6 + endstring

cfgbase = cfgbase + fortiroute + fortiroutev6

##############
# Output in text file
##############
cfgtrailer = """
config system settings
    set status disable
    set comments "%s"
end
config log memory setting
    set status disable
end
config log disk setting
    set status enable
end
end
""" % (namelang)

filename = customerID + ".txt"
cfgbase = dcnmText + ForcepointText + cfgbase + cfgtrailer

sys.stdout=open(filename,"w")
print (cfgbase)
sys.stdout.close()