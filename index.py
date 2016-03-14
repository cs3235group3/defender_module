from scapy.all import *

class ArpSniffer:
  """
  Creates a sniffer that collects the sniffed ARP packets
  """
  def __init__(self):
    self.packets = []

  def arp_monitor_callback(self, pkt):
    if ARP in pkt and pkt[ARP].op in (1,2): #who-has or is-at
        self.packets.append(pkt)

  def sniff_collect(self, num):
    # Reset the collected packets thus far
    if len(self.packets) != 0:
      self.packets = []
    sniff(prn=self.arp_monitor_callback, filter="arp", count=num)

  def is_at_packets(self):
    return filter(lambda x: x[ARP].op == 2, self.packets)

  def who_has_packets(self):
    return filter(lambda x: x[ARP].op == 1, self.packets)

  def dump(self):
    return self.packets

class ArpChecker:
  """
  An object that takes in a ARP packet and performs necessary checks
  """

  def __init__(self, packet):
    self.ether_src = packet[Ether].src
    self.ether_dst = packet[Ether].dst
    self.arp_src = packet[ARP].hwsrc
    self.arp_dst = packet[ARP].hwdst
  
  def header_consistency_check(self):
    return self.ether_src == self.arp_src and self.ether_dst == self.arp_dst

# Method 1
# This checks should only be done on the 'is-at' ARP packets
# ARP source MAC  != MAC header's source MAC
# ARP dest MAC    != MAC header's dest MAC
arp_sniffer = ArpSniffer()
arp_sniffer.sniff_collect(10)
foo = arp_sniffer.is_at_packets()
bar = foo[0]
bar.show()
# bar[ARP].show()
# bar[Ether].show()
check = ArpChecker(bar)
print check.header_consistency_check()

# Method 2
# Send TCP SYN to suspected spoofers
