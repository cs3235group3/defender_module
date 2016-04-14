from scapy.all import *

import thread
import time

# Use this program with the interactive Python shell

class ArpDefender:
  """
  Creates a sniffer that collects the sniffed ARP packets
  Performs verifications against spoofers
  """
  def __init__(self):
    self.replies = []
    self.packets = [] # temp storage for packets
    self.mapping = {} # stores the mapping of IP to MAC Address
    self.suspects = []
    self.checker = ArpChecker()

  # ===================================
  # Initialisation of program
  # ===================================
  # Sends out arp to all known hosts on the network
  # Caches the mapping
  # Note that this mapping is a weak claim: not absolutely perfect
  def determine_mapping(self):
    output = self.hosts_check()

    if type(output) == list:
      # Means got suspect
      print "There's someone performing ARP attacks on your network now."
      print [x for x in output]
    elif type(output) == dict:
      print "Initial MAC to IP mapping has been completed."
      print output

  def discover_all_hosts(self):
    # A really rudimentary way of getting all the hosts in your local area network >.<
    # Probably doesn't work for all cases
    a = ARP()
    self_ip = a.psrc
    subnet = ".".join(self_ip.split(".")[:3]) + ".*" # REALLY HACKY PLEASE FIND A BETTER WAY (if time permits)
    
    # Debug
    print subnet

    hosts = {} # key: IP address, value: MAC address
    ans, _ = arping(subnet)
    for answer in ans:
      arp_reply = answer[1]
      hosts[arp_reply.psrc] = arp_reply.hwsrc

    # Debug
    print hosts
    return hosts

  def hosts_check(self):
    # Runs discover_all_hosts 3 TIMES, see if there's a change in the mapping
    # If no change, assume that attacker has not started tampering (I probably need some justification for this)
    inconsistent = False
    suspects = []
    seed = self.discover_all_hosts()

    for i in range(2):
      updated = self.discover_all_hosts()
    
      for ip, mac in updated.items(): 
        if ip not in seed:
          seed[ip] = mac
        elif ip in seed:
          if seed[ip] == updated[ip]:
            pass # seed and update's ip to mac mapping agree with each other, nothing suspicious
          elif seed[ip] != updated[ip]:
            # Disagreements over ip to mac mapping, one of them must be wrong
            suspects.append(ip, seed[ip])
            suspects.append(ip, updated[ip])
            inconsistent = True

    if inconsistent:
      return suspects
    else:
      return seed

  # ===============================
  # Passive detection
  # ===============================
  def arp_who_has_callback(self, pkt):
    if ARP in pkt and pkt[ARP].op == 1: # who-has
      self.replies.append(pkt)

  def arp_is_at_callback(self, pkt):
    if ARP in pkt and pkt[ARP].op == 2: # is-at
      self.packets.append(pkt)

      # Debug
      # print self.checker.header_consistency_check(pkt)

      if not self.checker.header_consistency_check(pkt):
        print "Confirmed attacker at hwaddr: " + pkt[ARP].hwsrc + " pretending to be at IP address " + pkt[ARP].psrc
        self.suspects.append(pkt)

  def sniff_collect(self, num):
    # Stops sniffing after num packets of ARP packets have been collected
    # Does not take into account if they are is-at or who-has
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
  
  # Returns the correct MAC address for the ip address (if possible)
  def arp_full_cycle_check(self, ip_addr):
    # ip_addr is the IP address which you want to get the correct MAC address for    

    # Probing step
    # ans is the list of replies we get when we arping the ip address
    ans, unans = arping(ip_addr)
    if len(ans) == 1: 
      # only 1 reply, which means there are no spoofers
      return ans[ARP][hwsrc] # should be correct, haven't tested
      # return True 
      # wait should change this to return the mac address
    
    for answer in ans:
      # Send a TCP/SYN to confirm their identity  
      reply = tcp_syn_check(ip_addr)
      if reply is not None:
        return reply[ARP][hwsrc]
    
    return False # should never happen? might happen if host just happens to be down and there's no answer
    # from TCP syn check

  # Verifies the host's identity by sending a TCP/SYN packet
  def tcp_syn_check(self, ip_addr):
    ans, unans = sr(Ether()/IP(dst=ip_addr)/TCP(dport=80, flags="S"))
    # pkt = Ether()/IP(dst=ip_addr)/TCP(dport=80, flags="S")
    return ans

  def who_has(self, ip_addr):
    a = ARP()
    a.pdst = ip_addr
    send(a)

  # ===========================================
  # Probing check for ARP request half cycle
  # ===========================================  
  
  # Callback function for sniff
  # Essentially checks if the packet is an ARP is-at packet (aka response), 
  # and if it is, the engine will perform the necessary checks
  def request_half_cycle_callback(self):
    if ARP in pkt and pkt[ARP].op == 2: # is-at
      arp_full_cycle_check(pkt[ARP][pdst])



  # ===========================================
  # Probing check for ARP response half cycle
  # ===========================================

class ArpChecker:
  """
  An object that takes in a ARP packet and performs necessary checks
  """
  # Header consistency check won't work if Host A says IP B is at MAC Address of A
  # Header consistency check works against UNMODIFIED ARP packets
  # e.g. dest mac in mac header != dest mac in arp header
  def header_consistency_check(self, packet):
    packet.show()
    ether_src = packet[Ether].src
    ether_dst = packet[Ether].dst
    arp_src = packet[ARP].hwsrc
    arp_dst = packet[ARP].hwdst

    print (ether_src, ether_dst, arp_src, arp_dst)
    return ether_src == arp_src and ether_dst == arp_dst

d = ArpDefender()
d.determine_mapping()
# d.sniff_collect(5)

# Method 1
# This checks should only be done on the 'is-at' ARP packets
# ARP source MAC  != MAC header's source MAC
# ARP dest MAC    != MAC header's dest MAC
# arp_defender = ArpDefender()
# arp_defender.sniff_collect(5) # TODO: let user specify how many packets to listen to?
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








