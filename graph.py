import xml.etree.ElementTree as ET

root = ET.parse('output.xml').getroot()

def get_value(node, path):
  v = node.find(path)
  return v.text if v is not None else ''

class Port:

  def __init__(self, node, index, parent_type):
    self.type = get_value(node, 'TYPE')
    self.mac  = get_value(node, 'MACADDRESS')
    self.ip   = get_value(node, 'IP')

    main_switch = {
      'Pc': 1,
      'Pda': 1,
      'Cloud': 1,
      'Laptop': 1,
      'Printer': 1,
      'Server': 1,

      'AccessPoint': 2,
      'DslModem': 2,
      'Router': 2,
      'Sniffer': 2,
      'Switch': 2,
      'WirelessRouter': 2,
    }

    switch = {
      1: {
        'eAccessPointWirelessN': '{}',
        'eCopperCoaxial': '{}',
        'eCopperEthernet': 'Ethernet{}',
        'eCopperEthernet': 'FastEthernet{}',
        'eCopperFastEthernet': 'FastEthernet{}',
        'eCopperGigabitEthernet': 'GigabitEthernet{}',
        'eHostWirelessN': '{}',
        'eModem': '{}',
        'eSerial': '{}',
      },
      2: {
        'eAccessPointWirelessN': '{}',
        'eCopperCoaxial': '{}',
        'eCopperEthernet': 'Ethernet{}',
        'eCopperFastEthernet': 'FastEthernet0/{}',
        'eCopperGigabitEthernet': 'GigabitEthernet0/{}',
        'eHostWirelessN': '{}',
        'eModem': '{}',
        'eSerial': '{}',
      },
    }

    if self.type:
      self.name = switch[main_switch[parent_type]][self.type].format(index)

  def __repr__(self):
    return self.name if self.name else '<Unnamed>'

class Ports:

  def __init__(self, node):
    self.ports = []
    count = {}

    for p in node.findall('ENGINE/MODULE/SLOT/MODULE/PORT'):
      v = get_value(p, 'TYPE')
      if count.get(v, None) is None:
        count[v] = 0
      else:
        count[v] += 1
      self.ports.append(Port(p, count[v], node.find('ENGINE/TYPE').text))
    print(count)

  def by_name(self, name):
    # TODO map names to ports for close to linear access
    for device in self.ports:
      if device.name == name:
        return device


class Device:

  def __init__(self, node):
    self.node = node
    self.type = get_value(node, 'ENGINE/TYPE')
    self.name = get_value(node, 'ENGINE/NAME')
    self.id   = get_value(node, 'ENGINE/SAVE_REF_ID')

    self.ports = Ports(node)


class Devices:

  def __init__(self, nodes):
    self.devices = [Device(d) for d in nodes.findall('PACKETTRACER5/NETWORK/DEVICES/DEVICE')]

  def by_id(self, id):
    # TODO map id to devices for close to linear access
    for device in self.devices:
      if device.id == id:
        return device

  def by_index(self, index):
    return self.devices[int(index)]

devices = Devices(root)
links = root.find('PACKETTRACER5/NETWORK/LINKS')

with open('network.dot', 'w') as f:
  f.write('graph G {\n')
  f.write('\tnode [shape=record]\n\n')
  for link in links:
    fr = devices.by_id(link.find('CABLE/FROM').text)
    to = devices.by_id(link.find('CABLE/TO').text)
    fr_port = fr.ports.by_name(link.findall('CABLE/PORT')[0].text)
    to_port = to.ports.by_name(link.findall('CABLE/PORT')[1].text)
    f.write('\t"{}"--"{}" [taillabel="{}"; headlabel="{}"];\n'.format(
        fr.name,
        to.name,
        fr_port.ip if fr_port else '',
        to_port.ip if to_port else ''))
  f.write('}')
