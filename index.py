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
  def __init__(self):
    pass
  
  def header_consistency_check(self, packet):
    ether_src = packet[Ether].src
    ether_dst = packet[Ether].dst
    arp_src = packet[ARP].hwsrc
    arp_dst = packet[ARP].hwdst

    return ether_src == arp_src and ether_dst == arp_dst


# Method 1
# This checks should only be done on the 'is-at' ARP packets
# ARP source MAC  != MAC header's source MAC
# ARP dest MAC    != MAC header's dest MAC
arp_sniffer = ArpSniffer()
arp_sniffer.sniff_collect(5) # TODO: let user specify how many packets to listen to?
foo = arp_sniffer.is_at_packets()
bar = foo[0]
bar.show()
bar[ARP].show()
bar[Ether].show()
checker = ArpChecker()
print checker.header_consistency_check(bar)
# to check this consistency check, just use scapy's arping("192.168.0.*")



# Method 2
# Send TCP SYN to suspected spoofers

# Procedures:
# 1. Send an ARP 'who-has' packet
# 2. If received a lot of replies, send a TCP SYN packet to each of them
# 3. The one who replied is the real one








