import logging
import logging.handlers
import argparse
from configparser import ConfigParser
from phpipam_client import PhpIpamClient, GET, PATCH, POST
import sys
import ipaddress

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger()
logging.basicConfig(filename="new-vdom.log", filemode='a', format='%(asctime)s.%(msecs)03d %(levelname)s - %(funcName)s: %(message)s',  datefmt='%Y-%m-%d %H:%M:%S')
logger.setLevel(logging.DEBUG)

config = ConfigParser()

config.read('C:/Temp/Git/Fortinet/Fortigate/settings.ini')

ipamuser = config.get('IPAM', 'ipamuser')
ipamurl = config.get('IPAM', 'url')
ipampassword = config.get('IPAM', 'ipampassword')


parser = argparse.ArgumentParser(description='New VDOM config creator')

parser.add_argument("--c", required=True, type=str, help="z. B. customer012")
parser.add_argument("--n", required=True, type=str, help="z. B. Lampe")
parser.add_argument("--b", required=True, type=int, help="Blue VLAN ID 3152")
parser.add_argument("--r", type=int, help="Red VLAN ID 3589")
parser.add_argument("--g", type=int, help="Green VLAN ID 875")
parser.add_argument("--o", type=int, help="Orange VLAN ID 2215")

args = parser.parse_args()

cust = args.c
cname = args.n
intblue = args.b

nummer = cust.replace('customer','')
###
#intred = args.r
#intgreen = args.g
#intorange = args.o
###
idblue = 0
idred = 0
idgreen = 0
idorange = 0

cfgbase = """
config vdom
edit %s
config system interface
""" % (cust)

# IPAM Abfragen und IP Informationen ziehen
# ipam Konfiguration
ipam = PhpIpamClient(
    url=ipamurl,
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

for IPAMVlan in IPAMvlans:
    if int(IPAMVlan['number']) == intblue:
        idblue = IPAMVlan['vlanId']
    #if int(IPAMVlan['number']) == intgreen:
    #    idgreen = IPAMVlan['vlanId']
    #if int(IPAMVlan['number']) == intred:
    #    idred = IPAMVlan['vlanId']
    #if int(IPAMVlan['number']) == intorange:
    #    idorange = IPAMVlan['vlanId']

# blue 
querystring = "/vlan/" + idblue + "/subnets/"
blue = ipam.get(querystring)
for b in blue:
    idb = b['id']
    querystring = "/subnets/" + idb + "/addresses/"
    bb = ipam.get(querystring)
    for add in bb:
        if add['hostname'] == 'Fortigate':
            test = ipaddress.ip_address(add['ip'])
            if isinstance(test, ipaddress.IPv4Address):
                blueipv4 = add['ip'] + "/" + b['mask']
            if isinstance(test, ipaddress.IPv6Address):
                blueipv6 = add['ip'] + "/" + b['mask']

cfgblue = """
    edit "cust%s_blue"
	    set alias "cust%s_blue-Service"
        set vdom "%s"
        set status down
	    set ip %s
	    set allowaccess ping
        config ipv6
            set ip6-address %s
            set ip6-allowaccess ping
        set interface "Port-Channel12"
        set vlanid %s
    next
""" % (nummer, nummer, cust, blueipv4, blueipv6, intblue)

cfgbase = cfgbase + cfgblue

# green
if args.g:
    intgreen = args.g
    for IPAMVlan in IPAMvlans:
        if int(IPAMVlan['number']) == intgreen:
            idgreen = IPAMVlan['vlanId']
    
    querystring = "/vlan/" + idgreen + "/subnets/"
    green = ipam.get(querystring)
    for g in green:
        idg = g['id']
        querystring = "/subnets/" + idg + "/addresses/"
        gg = ipam.get(querystring)
        for addg in gg:
            if addg['hostname'] == 'Fortigate':
                test = ipaddress.ip_address(addg['ip'])
                if isinstance(test, ipaddress.IPv4Address):
                    greenipv4 = addg['ip'] + "/" + g['mask']
                if isinstance(test, ipaddress.IPv6Address):
                    greenipv6 = addg['ip'] + "/" + g['mask']
    cfggreen = """
    edit "cust%s_green"
	    set alias "cust%s_green-Server"
        set vdom "%s"
        set status down
        set ip %s
	    set allowaccess ping
        config ipv6
            set ip6-address %s
            set ip6-allowaccess ping
        set interface "Port-Channel11"
        set vlanid %s
    next
    """ % (nummer, nummer, cust, greenipv4, greenipv6, intgreen)
    cfgbase = cfgbase + cfggreen

# red
if args.r:
    intred = args.r
    for IPAMVlan in IPAMvlans:
        if int(IPAMVlan['number']) == intred:
            idred = IPAMVlan['vlanId']
    
    querystring = "/vlan/" + idred + "/subnets/"
    red = ipam.get(querystring)
    for r in red:
        idr = r['id']
        querystring = "/subnets/" + idr + "/addresses/"
        rr = ipam.get(querystring)
        for addr in rr:
            if addr['hostname'] == 'Fortigate':
                test = ipaddress.ip_address(addr['ip'])
                if isinstance(test, ipaddress.IPv4Address):
                    redipv4 = addr['ip'] + "/" + r['mask']
                if isinstance(test, ipaddress.IPv6Address):
                    redipv6 = addr['ip'] + "/" + r['mask']
    cfgred = """
    edit "cust%s_red"
	    set alias "cust%s_red-Extern"
        set vdom "%s"
        set status down
	    set ip %s
	    set allowaccess ping
        config ipv6
            set ip6-address %s
            set ip6-allowaccess ping
        set interface "Port-Channel13"
        set vlanid %s
    next
    """ % (nummer, nummer, cust, redipv4, redipv6, intred)
    cfgbase = cfgbase + cfgred


# orange
if args.o:
    intorange = args.o
    for IPAMVlan in IPAMvlans:
        if int(IPAMVlan['number']) == intorange:
            idorange = IPAMVlan['vlanId']
    
    querystring = "/vlan/" + idorange + "/subnets/"
    orange = ipam.get(querystring)
    for o in orange:
        ido = o['id']
        querystring = "/subnets/" + ido + "/addresses/"
        oo = ipam.get(querystring)
        for addo in oo:
            if addo['hostname'] == 'Fortigate':
                test = ipaddress.ip_address(addo['ip'])
                if isinstance(test, ipaddress.IPv4Address):
                    orangeipv4 = addo['ip'] + "/" + o['mask']
                if isinstance(test, ipaddress.IPv6Address):
                    orangeipv6 = addo['ip'] + "/" + o['mask']
    cfgorange = """
    edit "cust%s_orange"
	    set alias "cust%s_orange-Public"
        set vdom "%s"
        set status down
	    set ip %s
	    set allowaccess ping
        config ipv6
            set ip6-address %s
            set ip6-allowaccess ping
        set interface "Port-Channel14"
        set vlanid %s
    next
    """ % (nummer, nummer, cust, orangeipv4, orangeipv6, intorange)
    cfgbase = cfgbase + cfgorange


cfgtrailer = """
end
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
""" % (cname)

cfgbase = cfgbase + cfgtrailer

sys.stdout=open("test.txt","w")
print (cfgbase)
sys.stdout.close()