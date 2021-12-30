import http.client
import ssl
import base64
import string
import json
import copy
import os
from ipaddress import IPv4Interface
from ipaddress import IPv6Interface

from ipaddress import ip_network
from ipaddress import IPv6Network

from ipaddress import ip_address
from ipaddress import IPv6Address
from phpipam_client import PhpIpamClient, GET, PATCH, POST
from getpass import getpass
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

class IPAMSettings:
  ipamuser = str
  ipampassword = str
  url = str
  vlandomain = str
  def __init__(self, ipamuser, ipampassword, url, vlandomain):
    self.ipamuser = ipamuser
    self.ipampassword = ipampassword
    self.url = url
    self.vlandomain = vlandomain
  
  def __str__(self):
        return "Cred {0},{1},{2},{3}".format(self.ipamuser, self.ipampassword, self.url, self.vlandomain)

def IPAMSetup():
  folder = os.path.join(os.environ['USERPROFILE'], "Script-Settings")

  from configparser import ConfigParser
  config = ConfigParser()

  folder = folder.replace("\\","/")
  folder = folder + "/settings.ini"

  config.read(folder)

  dcnmuser = config.get('IPAM', 'ipamuser')
  #dcnmpassword = getpass()
  dcnmpassword = config.get('IPAM', 'ipampassword')
  dcnmserver = config.get('IPAM', 'url')
  vlandomain = config.get('IPAM', 'vlandomain')
  auth = IPAMSettings(dcnmuser, dcnmpassword, dcnmserver, vlandomain)
  return auth
  

class DCNMAuth:
  username = str
  password = str
  serverip = str
  def __init__(self, username, password, serverip):
    self.username = username
    self.password = password
    self.serverip = serverip
  
  def __str__(self):
        return "Cred {0},{1},{2}".format(self.username, self.password, self.serverip)
  
def AuthenticateDCNM():
  folder = os.path.join(os.environ['USERPROFILE'], "Script-Settings")

  from configparser import ConfigParser
  config = ConfigParser()

  folder = folder.replace("\\","/")
  folder = folder + "/settings.ini"

  config.read(folder)

  dcnmuser = config.get('DCNM', 'dcnmuser')
  #dcnmpassword = getpass()
  dcnmpassword = config.get('DCNM', 'dcnmpassword')
  dcnmserver = config.get('DCNM', 'dcnmserver')
  auth = DCNMAuth(dcnmuser, dcnmpassword, dcnmserver)
  return auth

def CLIGreen(bluevlanID):
  """Erstellen CLI fuer Fortimanager

  Args:
      bluevlanID (int): IPAM Vlan ID
      cust (str): customer123 Bezeichnung

  Returns:
      str: Fortigate CLI fuer Blue
  """
  config = ConfigParser()
  config.read('C:/Temp/Git/Fortinet/Fortigate/settings.ini')

  ipamuser = config.get('IPAM', 'ipamuser')
  ipampassword = config.get('IPAM', 'ipampassword')

  ipam = PhpIpamClient(
        url='https://ipam.consinto.com',
        app_id='network',
        username=ipamuser,
        ssl_verify=False,
        password=ipampassword,
        user_agent='myapiclient', # custom user-agent header
  )
  IPAMvlans = ipam.get('/vlan/', {
      'filter_by': 'vlanId',
      'filter_value': bluevlanID,
  })

  intblue = IPAMvlans[0]['number']

  return cfgblue

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

class MinimalNet:
  vlanId = str
  vlanName = str
  vrfName = str
  def __init__(self, vlanId, vlanName, vrfName):
    self.vlanId = vlanId
    self.vlanName = vlanName
    self.vrfName = vrfName
  
  def __str__(self):
    return "MinimalNet([{0},{1},{2}])".format(self.vlanId, self.vlanName, self.vrfName)

class MinimalVrf:
  vlanId = str
  vrfSegmentId = str
  vrfName = str
  def __init__(self, vlanId, vrfSegmentId, vrfName):
    self.vlanId = vlanId
    self.vrfSegmentId = vrfSegmentId
    self.vrfName = vrfName
  
  def __str__(self):
    return "MinimalNet([{0},{1},{2}])".format(self.vlanId, self.vrfSegmentId, self.vrfName)


class FabricSwitch:
  SwitchName = str
  Serial = str
  Fabric = str
  Routev4 = []
  Routev6 = []
  def __init__(self, SwitchName, Serial, Fabric):
    self.SwitchName = SwitchName
    self.Serial = Serial
    self.Fabric = Fabric

  def addRoutev4(self, r):
    self.Routev4 = copy.deepcopy(r)
  def addRoutev6(self, r):
    self.Routev6 = copy.deepcopy(r)
  
  def __str__(self):
    return "Switch([{0},{1},{2}])".format(self.SwitchName, self.Serial, self.Fabric)


class vrfVergleich:
  name = str
  vergleich = str

  def __init__(self, name):
    self.name = name
    self.vergleich = name.upper()

class Cb3VRF:
  vlanID = int
  vrfName = str
  vlanIPAMName = str
  vlanVNI = int
  IPAMid = int
  IPAMLayer3 = bool
  CB3Layer3 = bool
  ExistsInCB3 = bool
  ExistsInIPAM = bool
  CB3Deployed = bool
  Error = bool

  def __init__(self, vlanID, vrfName, ExistsInIPAM, IPAMid, vlanVNI, CB3Deployed):
    self.vlanID = vlanID
    self.vrfName = vrfName
    self.vlanIPAMName = None
    self.ExistsInIPAM = ExistsInIPAM
    self.ExistsInCB3 = True
    self.CB3Deployed = CB3Deployed
    self.IPAMid = IPAMid
    self.vlanVNI = vlanVNI
    self.CB3Layer3 = False
    self.IPAMLayer3 = False

  def setIPAMid(self, IPAMid):
    self.IPAMid = IPAMid

  def setvlanIPAMName(self, vlanIPAMName):
    self.vlanIPAMName = vlanIPAMName
  
  def __str__(self):
        return "VRF([{0},{1},{2},{3},{4},{5},{6}])".format(self.vlanID, self.vrfName, self.IPAMid, self.CB3Layer3, self.vlanVNI, self.vlanIPAMName, self.IPAMid)

class Cb3Vlan:
  vlanID = int
  vlanName = str
  vlanIPAMName = str
  vlanVNI = int
  IPAMVNI = int
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

  def __init__(self, vlanID, vlanName, ExistsInIPAM, ExistsInCB3, IPAMid, VRF, vlanVNI, CB3Deployed):
    self.vlanID = vlanID
    self.vlanName = vlanName
    self.vlanIPAMName = None
    self.ExistsInIPAM = ExistsInIPAM
    self.ExistsInCB3 = ExistsInCB3
    self.CB3Deployed = CB3Deployed
    self.IPAMid = IPAMid
    self.VRF = VRF
    self.vlanVNI = vlanVNI
    self.IPAMVNI = None
    self.IPv4Add = None
    self.IPv6Add = None
    self.CB3Layer3 = False
    self.IPAMLayer3 = False

  def setCB3Deployed(self):
    x = True
    self.CB3Deployed = bool(x)
  
  def setIPAMLayer3(self):
    x = True
    self.IPAMLayer3 = bool(x)

  def error(self):
    x = True
    self.Error = bool(x)

  def setvlanIPAMName(self, vlanIPAMName):
    self.vlanIPAMName = vlanIPAMName

  def setIPv4Network(self, IPv4Net):
    self.IPv4Net = IPv4Net
  
  def setIPv6Network(self, IPv6Net):
    self.IPv6Net = IPv6Net

  def setIPv4Address(self, IPv4Add):
    self.IPv4Add = IPv4Add
    self.CB3Layer3 = True

  def setIPv6Address(self, IPv6Add):
    self.IPv6Add = IPv6Add
    self.CB3Layer3 = True
  
  def setIPAMid(self, IPAMid):
    self.IPAMid = IPAMid
  
  def __str__(self):
        return "Network([{0},{1},{2},{3},{4},{5},{6},{7},{8},{9}])".format(self.vlanID, self.vlanName, self.VRF, self.IPAMid, self.IPv4Add, self.IPv6Add, self.CB3Layer3, self.vlanVNI, self.vlanIPAMName, self.IPAMid)
    

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
  #decoded = json.loads(jsonstr)
  return jsonstr

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