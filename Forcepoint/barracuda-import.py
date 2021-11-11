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

liste = []
listeS = []
listeD = []

data = pd.read_csv("C:/Temp/Git/Forcepoint/DMZ Regeln 8.11.2021.csv", sep = ';')

max = len(data.index)
for x in range(0, max):
    lines = data['Service'][x]
    if str(lines):
        lines = lines.split(",")
        for line in lines:
            liste.append(line.replace(" ",""))
#session.login(url=fcpoint, api_key=key, verify=False)
unique = list(set(liste))
zahl = 0
ref = "Ref:"
for u in unique:
    if ref in u:
        #print(u)
        zahl = zahl + 1
print("unique Service")
print(length_hint(unique))
print(zahl)
#Logout
#session.logout()

max = len(data.index)
for z in range(0, max):
    linesS = data['Source'][z]
    linesS = linesS.split(",")
    for lineS in linesS:
        listeS.append(lineS.replace(" ",""))

uniqueS = list(set(listeS))

#print(uniqueS)
print("unique Sources")
print(length_hint(uniqueS))
zahl = 0
ref = "Ref:"
for u in uniqueS:
    if ref in u:
        #print(u)
        zahl = zahl + 1
print(zahl)

###################

max = len(data.index)
for w in range(0, max):
    linesD = data['Destination'][w]
    linesD = linesD.split(",")
    for lineD in linesD:
        listeD.append(lineD.replace(" ",""))

uniqueD = list(set(listeD))

#print(uniqueD)
print("unique Destination")
print(length_hint(uniqueD))
zahl = 0
ref = "Ref:"
for ud in uniqueD:
    if ref in ud:
        #print(u)
        zahl = zahl + 1
print(zahl)