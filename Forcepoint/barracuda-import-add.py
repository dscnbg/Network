from smc import session
from smc.policy.layer3 import FirewallPolicy
from smc.policy.layer3 import FirewallSubPolicy
from smc.policy.layer3 import FirewallSubIpv6Policy
from smc.policy.layer3 import FirewallRule
from smc.policy.layer3 import FirewallTemplatePolicy
from smc.policy.rule_elements import LogOptions
from smc.policy.rule_elements import Action

from smc.elements.service import TCPService
from smc.elements.service import UDPService
from smc.elements.service import IPService
from smc.elements.service import ICMPService
from smc.elements.group import ServiceGroup


from smc.elements.network import Host, Alias
from smc.elements.network import Network
from smc.elements.group import GroupMixin, Group, ServiceGroup, TCPServiceGroup, UDPServiceGroup

import urllib3
urllib3.disable_warnings()
import json
import logging
import argparse

from operator import length_hint
import pandas as pd
#################
#
# Automatische Anlage von IPv4 Host und IPv6 Network Objekten incl. 
# Firewall Sub policies mit Basis Regelwerk (Outgoing HTTP/S NTP DNS) und verlinkung in die Main Policy
# Die Sub Policies werden in der Main Policy IPv4 und IPv6 im Bereich "Customer" von oben eingefügt.
#
# Das Skript benötigt die "fp-NGFW-SMC-python" Library https://github.com/Forcepoint/fp-NGFW-SMC-python
# Die Library unterstützt derzeit nicht die Anlage von IPv6 Sub Policies - dies wurde in der Library selbst abgeändert (layer3.py)
#
# Das Skript hat einen Test Namen sowie Test IP Adressen definiert.
# Bei mehrfacher ausführung (zu Vorführ Zwecken ;-) müssen die angelegten Rules, Policies sowie die Objekte händisch gelöscht werden.
# ACHTUNG: Gelöschte Objekte landen erst im "Trash". "Suchfunktion" -> "Trash" und Objekte endgültig löschen
#
# ToDo:
#   Plausi Prüfung der Eingabe
#   Variablen eingabe bei Aufruf des Skripts auf Kommando Zeile
#   Duplikatsprüfung der anzulegenden Objekte (wenn diese namentlich existieren bricht die Ausführung ab)
#   Try Catch Block
#
#################

##### Settings from settings.ini
from configparser import ConfigParser
config = ConfigParser()

config.read('C:/Temp/Git/Forcepoint/settings.ini')

fcpoint = config.get('FORCEPOINT', 'url')
key = config.get('FORCEPOINT', 'key')


#file = open('C:/Temp/Git/Forcepoint/Barracuda_DMZ.csv')
#csvreader = csv.reader(file)
#file.close()

session.login(url=fcpoint, api_key=key, verify=False)

services = []

#data = pd.read_csv("C:/Temp/Git/Forcepoint/DMZ Regeln 8.11.2021.csv", sep = ';')

services = ['UDP88', 'TCP9102', 'TCP10010', 'TCP8031', 'TCP51000', 'TCP53500', 'TCP57203', 'TCP8243', 'TCP9444', 'TCP7800', 'TCP42000', 'TCP3050', 'TCP84', 'TCP8081-8099', 'TCP3299', 'TCP5044', 'TCP8082', 'TCP9125', 'TCP3000', 'UDP123', 'TCP445', 'TCP464', 'TCP524', 'TCP60443', 'TCP7083', 'TCP49000-65000', 'UDP3478', 'TCP8482', 'TCP8103', 'TCP9981', 'TCP444', 'UDP6619', 'TCP53100', 'TCP1445', 'TCP49158', 'TCP512', 'UDP19302-19309', 'UDP464', 'TCP5666', 'TCP8000', 'TCP433', 'TCP25', 'TCP8081', 'TCP53', 'TCP30443', 'UDP138', 'TCP5269', 'TCP389', 'TCP8001', 'TCP8100', 'TCP5666', 'TCP8070', 'TCP5985', 'TCP12010', 'TCP49155', 'TCP44300', 'TCP3300-3399', 'TCP587', 'TCP9997-9998', 'TCP9090', 'TCP8444', 'TCP49161', 'UDP137', 'UDP6619', 'TCP4443', 'TCP49162', 'TCP4060', 'TCP49159', 'TCP9126', 'TCP55000', 'TCP4070', 'TCP110', 'UDP464', 'TCP465', 'TCP49163', 'TCP514', 'TCP1723', 'TCP3001', 'TCP84', 'TCP9997', 'TCP9125', 'TCP8050', 'TCP3200-3299', 'TCP8050', 'TCP9126', 'TCP1352', 'TCP2025', 'TCP5000', 'TCP5080', 'TCP8888', 'TCP49165', 'TCP9014', 'TCP50000', 'TCP49156', 'TCP8449', 'TCP8200', 'TCP56000', 'TCP82', 'TCP1667', 'TCP5986', 'TCP8018', 'TCP1723', 'TCP6263', 'TCP49160', 'TCP12489', 'TCP1194', 'TCP5002', 'TCP44380', 'TCP993', 'TCP10101', 'TCP5061', 'TCP3306', 'TCP465', 'TCP643', 'TCP8080', 'TCP88', 'TCP8010', 'TCP6264', 'TCP443', 'TCP8400', 'TCP49157', 'TCP9200', 'TCP9013', 'TCP9000', 'UDP749', 'TCP10080', 'TCP80', 'TCP8004', 'TCP12489', 'TCP543', 'TCP43000', 'UDP389', 'TCP3389', 'UDP135', 'TCP49164', 'TCP995', 'TCP89', 'TCP8017', 'TCP5081', 'TCP44300', 'TCP5090', 'TCP16204', 'TCP749', 'TCP3299', 'TCP3128', 'TCP135', 'TCP5269', 'TCP513', 'TCP8088', 'TCP8200', 'TCP636', 'TCP5250', 'TCP8081-8099', 'UDP161', 'UDP500', 'TCP8440', 'TCP139', 'UDP4500', 'TCP10443', 'TCP8771', 'TCP6556', 'TCP5085', 'TCP81', 'TCP9200', 'TCP8002', 'TCP4084', 'TCP5084']
tcp = "TCP"
udp = "UDP"
dele = "-"
unique = list(set(services))
for serv in unique:
    if tcp in serv:
        if dele in serv:
            print(serv)
            continue
        name = serv.replace("UDP","UDP-")
        port = serv.replace("UDP", "")
        #print(name)
        #print(port)
        #UDPService.create(name, port, comment='Barracuda Import')
#ref = "Ref:"
#print(length_hint(services))
#print(length_hint(unique))
name = "TCP-1111"
port = "1111"


"""
max = len(data.index)
for x in range(0, max):
    line = data['Service'][x]
    line = line.replace(" ", "")
    line = line.split(",")
    for l in line:
        if ref in l:
            next
        else:
            services.append(l)
    

uniqueS = list(set(services))
print(uniqueS)
print(length_hint(uniqueS))
#unique = list(set(liste))
#print(length_hint(unique))
#Logout
"""
session.logout()
