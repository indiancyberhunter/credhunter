
#!/usr/bin/env python3 
#----------------------------------------------------------------------------
# Created By  : cyb3rhun73r
# version ='1.0'
# ---------------------------------------------------------------------------

import scapy.all as scapy
import argparse
from scapy.layers import http

#colorcode
class bcolors:
    OK = '\033[92m' #GREEN
    WARNING = '\033[93m' #YELLOW
    FAIL = '\033[91m' #RED
    RESET = '\033[0m' #RESET COLOR

#Title
auth = """
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
#                         _            _ _ _ _ _ _  _ _ _ _ _ _   _ _ _ _ _       _ _ _ _ _           #
#  |     | |       |     / \        /            /             | |         |     |         | \     /  #          
#  |     | |       |    /   \      /            /              | |         |     |         |  \   /   #
#  |=====| |       |   /     \    /            /    = = = = = =| |_ _ _ _ _|     |_ _ _ _ _|   \ /    #
#  |     | |       |  /       \  /            /                | |\           _  |              |     #
#  |     |  \ _ _ /  /         \/            /      _ _ _ _ _ _| | \         |_| |              |     #
#                                                                                                     #  
#                                                                                                     #      
#                               Sensitive Data Exposure Detector                                      #  
#                                     Developer:CYB3RHUN73R                                           #  
#                                         VERSION:1.0                                                 #  
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
       """
print(bcolors.FAIL + auth + bcolors.RESET)


#help info
def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Specify interface on which to sniff packets")
    arguments = parser.parse_args()
    return arguments.interface

#Interface_Input

def sniff(iface):
    scapy.sniff(iface=iface, store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print(bcolors.OK + "[+] Http Request >> " + str(packet[http.HTTPRequest].Host) + str(packet[http.HTTPRequest].Path) + bcolors.RESET)
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            print(bcolors.WARNING + "\n[+] Possible username/password >> " + str(load) +"\n")
            
#execution_starting_from_here
iface = get_interface() 
print(bcolors.WARNING + "[~]Monitoring the packets for the sensitive information[~]" + bcolors.RESET)
sniff(iface)

