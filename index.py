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

  # For user to specify his submask
  def user_submask(self, ip):
    pass

  def determine_mapping(self):
    output = self.hosts_check()

    if type(output) == list:
      # Means got suspect
      print "There's someone performing ARP attacks on your network now."
      print [x for x in output]
    elif type(output) == dict:
      print "Initial MAC to IP mapping has been completed."
      self.mapping = output
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
  # Main interface
  # ===============================  
  # Methods here are called by main.py, essentially a callback that 
  # takes in the sniffed packet that the main thread passes to it,
  # amd tells if the packet is legit or not
  def arp_callback(self, pkt):
    # First line of defence, check if headers are consistent
    if pkt[ARP].op == 2:
      if not self.checker.header_consistency_check(pkt):
        print "Confirmed attacker at hwaddr: " + pkt[ARP].hwsrc + " pretending to be at IP address " + pkt[ARP].psrc

    # Second line of defence
    # Active mitigation
    if ARP in pkt and pkt[ARP].op == 1:  
      if pkt[ARP].psrc not in self.mapping:
        if not self.tcp_syn_check(pkt[ARP].psrc)[0]:
          print "Someone could be attacking your network"
    elif ARP in pkt and pkt[ARP].op == 2:
      # Not checking if anyone within the time interval sent out a request
      if not self.arp_full_cycle_check(pkt[ARP].pdst):
        print "Someone could be attacking your network"

      # If a valid MAC address is returned, then there is no cause for alarm, hence nothing happens

  def run(self):
    # sniff(prn=self.arp_callback, filter="arp", iface="en0")
    # sniff(prn=self.arp_callback, filter="arp")
    # sniff(prn=self.simple_header_callback, filter="arp")

    sniff(prn=self.simple_check_callback, filter="arp")

  def simple_check_callback(self, pkt):
    if pkt[ARP].op == 2:
      # print pkt[ARP].psrc # e.g. 192.168.0.100

      # Check if the headers are malformed
      if not self.checker.header_consistency_check(pkt):
        print "The ARP and Ethernet headers are not the same"
        print "ARP MAC is {} but Ethernet MAC is {}".format(pkt[ARP].hwsrc, pkt[Ether].src)

      # Check if it's consistent with the database
      if pkt[ARP].psrc in self.mapping:
        if self.mapping[pkt[ARP].psrc] != pkt[Ether].src:
          print "{} -> {} does not match the IP to MAC mapping database".format(pkt[ARP].psrc, pkt[Ether].src)
          print "{} -> {} is the mapping in the database".format(pkt[ARP].psrc, self.mapping[pkt[ARP].psrc]) 
        else:
          print "{} -> {} agrees with information in IP to MAC mapping database".format(pkt[ARP].psrc, pkt[Ether].src)

  def simple_header_callback(self, pkt):
    if pkt[ARP].op == 2:
      pkt.show()
      if not self.checker.header_consistency_check(pkt):
        print "kena attacked"
    else:
      print "not a malicious packet"



  # ===================================
  # Probing check for ARP full cycle
  # ===================================

  # Returns the correct MAC address for the ip address (if possible)
  # ip_addr is the IP address which you want to get the correct MAC address for
  # Returns (<boolean>, <string>)
  def arp_full_cycle_check(self, ip_addr):    

    # Probing step
    # ans is the list of replies we get when we arping the ip address
    ans, unans = arping(ip_addr)
    
    # NO SPOOFER
    # Only 1 reply, which means there are no spoofers
    if len(ans) == 1:
      # Sample reply
      # (<Ether  dst=ff:ff:ff:ff:ff:ff type=0x806 |<ARP  pdst=192.168.0.100 |>>, <Ether  dst=3c:15:c2:c4:d9:0a src=34:be:00:4e:2a:74 type=0x806 |<ARP  hwtype=0x1 ptype=0x800 hwlen=6 plen=4 op=is-at hwsrc=34:be:00:4e:2a:74 psrc=192.168.0.100 hwdst=3c:15:c2:c4:d9:0a pdst=192.168.0.103 |>>)]
      return (True, ans[0][1].src)

    # SPOOFERS EXIST
    # In the event where > 1 host replies to the ARP ping
    # this method is fucked i need to see what the fuck arping replies
    for answer in ans:
      # Send a TCP/SYN to confirm their identity
      ans = tcp_syn_check(ip_addr)

      # Need to edit this function too because I have no idea what ans is when the reply is legit
      if ans[0]:
        return (True, ans[1][ARP].hwsrc)

    return (False, "") # should never happen? might happen if host just happens to be down and there's no answer
    # from TCP syn check

  # Verifies the host's identity by sending a TCP/SYN packet
  # Returns (<boolean>, response)
  def tcp_syn_check(self, ip_addr):
    scan_response = sr1(IP(dst=ip_addr)/TCP(dport=80, flags="S"), timeout=2)

    if not scan_response:
      return (False, [])
    else:
      return (True, scan_response) # need to edit this, I don't know what a legit scan_response looks like

  def who_has(self, ip_addr):
    a = ARP()
    a.pdst = ip_addr
    send(a)

  # ===========================================
  # Probing check for ARP request half cycle
  # ===========================================

  def request_half_cycle_callback(self, pkt):
    if ARP in pkt and pkt[ARP].op == 1:
      if pkt[ARP].psrc not in self.mapping:
        if not tcp_syn_check(pkt[ARP].psrc):
          print "Someone could be attacking your network"

  # ===========================================
  # Probing check for ARP response half cycle
  # ===========================================

  # Callback function for sniff
  # Essentially checks if the packet is an ARP is-at packet (aka response),
  # and if it is, the engine will perform the necessary checks
  def response_half_cycle_callback(self, pkt):
    if ARP in pkt and pkt[ARP].op == 2: # is-at
      # IDEALLY check if anyone in the time interval sent out a request for this

      # Not checking if anyone within the time interval sent out a request
      if not arp_full_cycle_check(pkt[ARP].pdst):
        print "Someone could be attacking your network"

      # If a valid MAC address is returned, then there is no cause for alarm, hence nothing happens



class ArpChecker:
  """
  An object that takes in a ARP packet and performs necessary checks
  """
  # Header consistency check won't work if Host A says IP B is at MAC Address of A
  # Header consistency check works against UNMODIFIED ARP packets
  # e.g. dest mac in mac header != dest mac in arp header
  def header_consistency_check(self, packet):
    # packet.show()

    ether_src = packet[Ether].src
    ether_dst = packet[Ether].dst
    arp_src = packet[ARP].hwsrc
    arp_dst = packet[ARP].hwdst

    if packet[ARP].op == 2:
      return ether_src == arp_src and ether_dst == arp_dst
    else:
      return ether_src == arp_src
    
    # print (ether_src, ether_dst, arp_src, arp_dst)

d = ArpDefender()
print "Initial host mapping: " + str(d.mapping)
d.determine_mapping()
d.run()
print d.mapping
# d.tcp_syn_check("192.168.0.100")
# d.run()
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

