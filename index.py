from scapy.all import *

import thread
import time

class ArpDefender:
  """
  Creates a sniffer that collects the sniffed ARP packets
  Performs verifications against spoofers
  """
  def __init__(self):
    self.replies = []
    self.packets = []
    self.mapping = {} # stores the mapping of IP to MAC Address
    self.suspects = []
    self.checker = ArpChecker()

  # ===============================
  # Passive detection
  # ===============================
  def arp_is_at_callback(self, pkt):
    if ARP in pkt and pkt[ARP].op == 2: # is-at
      self.packets.append(pkt)

    if not self.checker.header_consistency_check(pkt):
      print "Confirmed attacker at hwaddr: " + pkt[ARP].hwsrc + " pretending to be at IP address " + pkt[ARP].psrc
      self.suspects.append(pkt)

  def sniff_collect(self, num):
    # Stops sniffing after num packets of ARP packets have been collected
    sniff(prn=self.arp_is_at_callback, filter="arp", count=num) 

  def is_at_packets(self):
    return filter(lambda x: x[ARP].op == 2, self.packets)

  def get_all_packets(self):
    return self.packets

  def get_suspects(self):
    return self.suspects

  # ===================================
  # Probing check for ARP full cycle
  # ===================================
  def arp_who_has_callback(self, pkt):
    if ARP in pkt and pkt[ARP].op == 1: # who-has
      self.replies.append(pkt)

  # Sends out arp to all known hosts on the network
  # Caches the mapping
  def determine_mapping(self):
    pass

  def discover_all_hosts():
    # A really rudimentary way of getting all the hosts in your local area network >.<
    # Probably doesn't work for all cases
    a = ARP()
    self_ip = a.psrc
    subnet = ".".join(self_ip.split(".")) + ".*" # REALLY HACKY

    hosts = {} # key: IP address, value: MAC address
    ans, _ = arping(subnet)
    for answer in ans:
      arp_reply = answer[1]
      hosts[arp_reply.psrc] = arp_reply.hwsrc

    # Debug
    print hosts

  def arp_full_cycle_check(self, ip_addr):
    # ip_addr is the IP address which you want to get the correct MAC address for    

    # Probing step
    ans, unans = arping(ip_addr)
    if len(ans) == 1: 
      return True # only 1 reply, which means there are no spoofers
      # wait should change this to return the mac address
    
    for answer in ans:
      # Send a TCP/SYN to confirm their identity  
      reply = tcp_syn_check(ip_addr)
      if reply is not None:
        return 
    
    return False # should never happen?

  # Verifies the host's identity by sending a TCP/SYN packet
  def tcp_syn_check(self, ip_addr):
    ans, unans = sr(Ether()/IP(dst=ip_addr)/TCP(dport=80, flags="S"))
    return ans    

  def who_has(self, ip_addr):
    a = ARP()
    a.pdst = ip_addr
    send(a)

class ArpChecker:
  """
  An object that takes in a ARP packet and performs necessary checks
  """
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
arp_defender = ArpDefender()
arp_defender.sniff_collect(5) # TODO: let user specify how many packets to listen to?
# foo = arp_defender.is_at_packets()
# bar = foo[0]
# bar.show()
# bar[ARP].show()
# bar[Ether].show()
# checker = ArpChecker()
# print checker.header_consistency_check(bar)
# to check this consistency check, just use scapy's arping("192.168.0.*")

# arp_defender.sniff_loop()

# Method 2
# Send TCP SYN to suspected spoofers

# Procedures:
# 1. Send an ARP 'who-has' packet
# 2. If received a lot of replies, send a TCP SYN packet to each of them
# 3. The one who replied is the real one








