from fortifunctions import GetFortiApiToken
from fortifunctions import GetFortiApi
from fortifunctions import append_df_to_excel

import pandas as pd
import xlrd

#####################################################
#
# Das Skript fragt die Fortigate vdom DOP_DGWAN ab und zieht die router info.
# Routen werden gefiltert (unerwuenschte routen) und anschliessend
# in das excel routes.xlsx abgelegt, sollten diese dort noch nicht vorhanden sein.
# Die pruefung geschieht rein additiv, ueberfluessige routen werden nicht geloescht.
#
#####################################################

# unerwuenschte routen
subst108 = '10.0.0.0/8'
subst101 = '10.1.0.0/16'
subst109 = '10.9.'
subst185 = '185.213.'
subst194 = '194.'
subst32 = '/32'
# Pandas Settings und Excel Sheet vorbereiten - default settings fuer die routen werden gesetzt
livedata = pd.read_excel('C:/Temp/Git/Cisco/DCNM/routes.xlsx', sheet_name='IPv4')
maximum = len(livedata.index)
rname = 'DGWAN-STANDORTNETZ'
tag = 59998
vrfname = 'dop_intern'
nexthop = '100.64.252.63'
df = pd.DataFrame(columns=('IP_PREFIX', 'NEXT_HOP_IP', 'VRF_NAME', 'TAG', 'RNAME'))
existiert = False
list_of_lists = []
##### Settings from settings.ini, username, pw, port, fortigate ip
from configparser import ConfigParser
config = ConfigParser()

config.read('C:/Temp/Git/Fortinet/Fortigate/settings.ini')

user = config.get('FORTIGATE', 'user')
password = config.get('FORTIGATE', 'password')
server = config.get('FORTIGATE', 'address')
port = config.get('FORTIGATE', 'port')
######

# sessionaufbau
session = GetFortiApiToken(server, user, password, port)

vdom = 'DOP_DGWAN'
uri = 'https://' + server + ':' + port + '/api/v2/monitor/router/ipv4/?vdom=' + vdom
ipv4route = GetFortiApi(session, uri, vdom)

# filtern der unerwuenschten routen und abgleich mit der routes.xlsx auf doppelte eintraege
for routes in ipv4route:
    existiert = False
    if subst108 in routes['ip_mask']:
        continue
    if subst101 in routes['ip_mask']:
        continue
    if subst32 in routes['ip_mask']:
        continue
    if subst109 in routes['ip_mask']:
        continue
    if subst185 in routes['ip_mask']:
        continue
    if subst194 in routes['ip_mask']:
        continue
    for x in range(0, maximum):
        if (livedata['IP_PREFIX'][x] == routes['ip_mask']) and (livedata['VRF_NAME'][x] == vrfname):
            existiert = True
    if (existiert == False):
        list_of_lists.append([routes['ip_mask'], nexthop, vrfname, tag, rname])    
    
    
# export aufarbeiten
excel = pd.DataFrame(list_of_lists, columns=('IP_PREFIX', 'NEXT_HOP_IP', 'VRF_NAME', 'TAG', 'RNAME'))

# export in die gold excel und eine pruef excel
print(excel)
append_df_to_excel('C:/Temp/Git/Fortinet/Fortigate/routes.xlsx', excel, header=None, sheet_name='IPv4', index=False)
append_df_to_excel('C:/Temp/Git/Cisco/DCNM/routes.xlsx', excel, header=None, sheet_name='IPv4', index=False)