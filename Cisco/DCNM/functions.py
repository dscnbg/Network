import http.client
import ssl
import base64
import string
import json
import copy

from ipaddress import IPv4Interface
from ipaddress import IPv6Interface

from ipaddress import ip_network
from ipaddress import IPv6Network

from ipaddress import ip_address
from ipaddress import IPv6Address

#__author__ = "Louis Jia"
#__copyright__ = "Copyright (C) 2018 Cisco System"

class v4Route:
  id = int
  Prefix = ip_network
  NextHop = ip_address
  vrf = str
  desc = str
  tag = int
  exists = bool
  ignore = bool
  def __init__(self, id, Prefix, NextHop, vrf, desc, tag):
    self.id = id
    self.Prefix = Prefix
    self.NextHop = NextHop
    self.vrf = vrf
    self.desc = desc
    self.tag = tag
    self.exists = False
  def setExists(self):
    self.exists = True
  def setIgnore(self):
    self.ignore = True


class v6Route:
  id = int
  Prefix = IPv6Network
  NextHop = IPv6Address
  vrf = str
  desc = str
  tag = int
  exists = bool
  ignore = bool
  def __init__(self, id, Prefix, NextHop, vrf, desc, tag):
    self.id = id
    self.Prefix = Prefix
    self.NextHop = NextHop
    self.vrf = vrf
    self.desc = desc
    self.tag = tag
    self.exists = False
  def setExists(self):
    self.exists = True
  def setIgnore(self):
    self.ignore = True

class FabricSwitch:
  SwitchName = str
  Serial = str
  Routev4 = []
  Routev6 = []
  def __init__(self, SwitchName, Serial):
    self.SwitchName = SwitchName
    self.Serial = Serial

  def addRoutev4(self, r):
    self.Routev4 = copy.deepcopy(r)
  def addRoutev6(self, r):
    self.Routev6 = copy.deepcopy(r)

class vrfVergleich:
  name = str
  vergleich = str

  def __init__(self, name):
    self.name = name
    self.vergleich = name.upper()

class Cb3Vlan:
  vlanID = int
  vlanName = int
  vlanVNI = int
  IPAMid = int
  VRF = str
  IPAMLayer3 = bool
  CB3Layer3 = bool
  ExistsInCB3 = bool
  ExistsInIPAM = bool
  CB3Deployed = bool
  Error = bool
  IPv4Add = ip_address
  IPv6Add = IPv6Address
  IPv4Net = ip_network
  IPv6Net = IPv6Network

  def __init__(self, vlanID, vlanName, ExistsInIPAM, IPAMid, VRF):
    self.vlanID = vlanID
    self.vlanName = vlanName
    self.ExistsInIPAM = ExistsInIPAM
    self.ExistsInCB3 = False
    self.CB3Deployed = False
    self.IPAMid = IPAMid
    self.VRF = VRF

  def setCB3Deployed(self):
    x = True
    self.CB3Deployed = bool(x)

  def error(self):
    x = True
    self.Error = bool(x)

  def setIPv4Network(self, IPv4Net):
    self.IPv4Net = IPv4Net
  
  def setIPv6Network(self, IPv6Net):
    self.IPv6Net = IPv6Net

  def setIPv4Address(self, IPv4Add):
    self.IPv4Add = IPv4Add

  def setIPv6Address(self, IPv6Add):
    self.IPv6Add = IPv6Add
    

def getRestToken(username, password, serverip):
  ssl._create_default_https_context = ssl._create_unverified_context

  ##replace server ip address here
  conn = http.client.HTTPSConnection(serverip)

  payload = "{\"expirationTime\" : 10000000000}\n"

  ## replace user name and password here
  authenStr="%s:%s" % (username, password)

  base64string = base64.encodebytes(bytes(authenStr, 'utf-8'))
  tmpstr= "Basic %s" % base64string
  authorizationStr = tmpstr.replace("b\'","").replace("\\n\'","")
  #print(authorizationStr)

  headers = {
      'content-type': "application/json",
      'authorization': authorizationStr,
      'cache-control': "no-cache"
      }

  conn.request("POST", "/rest/logon", payload, headers)

  res = conn.getresponse()
  #print(res.status, res.reason)
  data = res.read()
  longstr=data.decode("utf-8")
  strArr=longstr.split("\"")
  return strArr[3]


def  getVRFVLAN(serverip, resttoken):
  ssl._create_default_https_context = ssl._create_unverified_context
 
  conn = http.client.HTTPSConnection(serverip)

  headers = {
    'dcnm-token': resttoken,
    'content-type': "application/x-www-form-urlencoded",
    'cache-control': "no-cache"
    }


  conn.request("GET", "/rest/resource-manager/vlan/MSD001?vlanUsageType=TOP_DOWN_VRF_VLAN", headers=headers)

  res = conn.getresponse()
  data = res.read()
  jsonstr=data.decode("utf-8")
  decoded = json.loads(jsonstr)
  

  return decoded

def  getNetworks(serverip, resttoken):
  ssl._create_default_https_context = ssl._create_unverified_context
 
  conn = http.client.HTTPSConnection(serverip)

  headers = {
    'dcnm-token': resttoken,
    'content-type': "application/x-www-form-urlencoded",
    'cache-control': "no-cache"
    }


  conn.request("GET", "/rest/top-down/fabrics/MSD001/networks", headers=headers)

  res = conn.getresponse()
  data = res.read()
  jsonstr=data.decode("utf-8")
  decoded = json.loads(jsonstr)
  

  return decoded

def  getVRF(serverip, resttoken):
  ssl._create_default_https_context = ssl._create_unverified_context
 
  conn = http.client.HTTPSConnection(serverip)

  headers = {
    'dcnm-token': resttoken,
    'content-type': "application/x-www-form-urlencoded",
    'cache-control': "no-cache"
    }


  conn.request("GET", "/rest/top-down/fabrics/MSD001/vrfs", headers=headers)

  res = conn.getresponse()
  data = res.read()
  jsonstr=data.decode("utf-8")
  decoded = json.loads(jsonstr)
  

  return decoded

def  returnVRF(vrf, dcnmserver, token):
  # VRF Case Sensitive / Vergleich mit DCNM
  uri = "/rest/top-down/v2/fabrics/MSD001/vrfs"

  result = DCNMget(uri, dcnmserver, token)
  vergleich = []

  for results in result:
    wip = results['vrfName']
    vergleich.append(vrfVergleich(wip))

  for vgl in vergleich:
    if (vrf.upper() == vgl.vergleich):
      return vgl.name

  return 0
    

def  DCNMget(uri, serverip, resttoken):
  ssl._create_default_https_context = ssl._create_unverified_context
 
  conn = http.client.HTTPSConnection(serverip)

  headers = {
    'dcnm-token': resttoken,
    'content-type': "application/x-www-form-urlencoded",
    'cache-control': "no-cache"
    }


  conn.request("GET", uri, headers=headers)

  res = conn.getresponse()
  data = res.read()
  jsonstr=data.decode("utf-8")
  decoded = json.loads(jsonstr)
  

  return decoded

def DCNMPost(payload, uri, serverip, restToken):
  ssl._create_default_https_context = ssl._create_unverified_context
  headers = {
    'dcnm-token': restToken,
    'content-type': "application/json"
    }

  ##replace server ip address here
  conn = http.client.HTTPSConnection(serverip)

  conn.request("POST", uri, payload, headers)

  res = conn.getresponse()
  data = res.read()
  jsonstr=data.decode("utf-8")
  decoded = json.loads(jsonstr)
  return decoded

def DCNMPost2(payload, uri, serverip, restToken):
  ssl._create_default_https_context = ssl._create_unverified_context
  headers = {
    'dcnm-token': restToken,
    'content-type': "application/json"
    }

  ##replace server ip address here
  conn = http.client.HTTPSConnection(serverip)

  conn.request("POST", uri, payload, headers)
  
  res = conn.getresponse()
  print(res.status, res.reason)
  #data = res.read()
  #jsonstr=data.decode("utf-8")
  #decoded = json.loads(jsonstr)
  return res