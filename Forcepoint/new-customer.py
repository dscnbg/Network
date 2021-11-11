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

import urllib3
urllib3.disable_warnings()
import json
import logging
import argparse
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

######


#Login
session.login(url=fcpoint, api_key=key, verify=False)

#################
#Namensgebung
#################

parser = argparse.ArgumentParser(description='Neuanlage Kunde auf Forcepoint')

parser.add_argument("--c", required=True, type=str, help="customer mit Kürzel customer003-MEF")
parser.add_argument("--n", required=True, type=str, help="NAT IP z. B. 185.213.32.15")
parser.add_argument("--p", required=True, type=str, help="IPv6 Prefix /56 Network z. B. 2a0c:ed80:123::/56")

args = parser.parse_args()

cname = args.c
NATIP = args.n
IPV6Network = args.p

#################
#Strings zusammen bauen
#################

cnameV4 = cname + '-v4'
cnameV6 = cname + '-v6'
cnameNAT = cname + '-NAT'

#################
#Host NAT Element erstellen
#################

Host.create(name=cnameNAT, address=NATIP, comment='Erstellt via Script')

#################
#Network IPv6 Element erstellen
#################

Network.create(name=cnameV6, ipv6_network=IPV6Network, comment='Erstellt via Script')

#################
#IPv6 Sub Policy erstellen
#################

p = FirewallSubIpv6Policy.create(name=cnameV6)
p.fw_ipv6_access_rules.create_rule_section(name='Outbound')
p.fw_ipv6_access_rules.create(name='Default Outgoing', sources=[Network(cnameV6)], destinations='any', services=[TCPService('SSH'), TCPService('HTTP'), TCPService('HTTPS'), UDPService('NTP (UDP)'), ServiceGroup('DNS')], action='allow', after='Outbound')
p.fw_ipv6_access_rules.create_rule_section(name='Inbound', add_pos=30)

#################
#IPv4 Sub Policy erstellen
#################

q = FirewallSubPolicy.create(name=cnameV4)
q.fw_ipv4_access_rules.create_rule_section(name='Outbound')
q.fw_ipv4_access_rules.create(name='Default Outgoing', sources=[Host(cnameNAT)], destinations='any', services=[TCPService('SSH'), TCPService('HTTP'), TCPService('HTTPS'), UDPService('NTP (UDP)'), ServiceGroup('DNS')], action='allow', after='Outbound')
q.fw_ipv4_access_rules.create_rule_section(name='Inbound', add_pos=30)

#################
#Jump Points einfügen
#Zur vorsicht in die nicht genutzt Policy "Zweite Policy für Firewall XY"
#################

v4inboundpol = cname + 'v4-In'
v4outbound = cname + 'v4-Out'

subv4 = FirewallSubPolicy(cnameV4)
injectv4 = FirewallPolicy('Default Edge Policy')

# Beim Anlegen der fw_ipv4_access_rules.create funktioniert das Keyword after='Customer' nicht - deshalb ein späterer Move der Regel und das Ausfindig Machen der Rule Section
for rule in injectv4.fw_ipv4_access_rules.all():
        if rule.is_rule_section == True:
            if rule.comment == 'Customer':
                r = rule


#forward
newrule = injectv4.fw_ipv4_access_rules.create(name=v4outbound, sources=[Host(cnameNAT)], destinations='any', services='any', action='jump', sub_policy=subv4)
newrule.move_rule_after(r)
#reverse
newrule = injectv4.fw_ipv4_access_rules.create(name=v4inboundpol, sources='any', destinations=[Host(cnameNAT)], services='any', action='jump', sub_policy=subv4)
newrule.move_rule_after(r)

#v6

v6inboundpol = cname + 'v6-In'
v6outbound = cname + 'v6-Out'

subv6 = FirewallSubIpv6Policy(cnameV6)
injectv6 = FirewallPolicy('Default Edge Policy')

# Beim Anlegen der fw_ipv4_access_rules.create funktioniert das Keyword after='Customer' nicht - deshalb ein späterer Move der Regel und das Ausfindig Machen der Rule Section
for rulev6 in injectv6.fw_ipv6_access_rules.all():
        if rulev6.is_rule_section == True:
            if rulev6.comment == 'Customer':
                rv6 = rulev6

#forward
newrulev6 = injectv4.fw_ipv6_access_rules.create(name=v6outbound, sources=[Network(cnameV6)], destinations='any', services='any', action='jump', sub_policy=subv6)
newrulev6.move_rule_after(rv6)
#reverse
newrulev6 = injectv4.fw_ipv6_access_rules.create(name=v6inboundpol, sources='any', destinations=[Network(cnameV6)], services='any', action='jump', sub_policy=subv6)
newrulev6.move_rule_after(rv6)


#Logout
session.logout()
