
#!/usr/bin/env python3 
#----------------------------------------------------------------------------
# Created By  : cyb3rhun73r
# version ='1.0'
# ---------------------------------------------------------------------------

import scapy.all as scapy
import argparse
from scapy.layers import http

class bcolors:
    OK = '\033[92m' #GREEN
    WARNING = '\033[93m' #YELLOW
    FAIL = '\033[91m' #RED
    RESET = '\033[0m' #RESET COLOR

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
#                                    Developer:CYB73R_HUN73R                                          #  
#                                         VERSION:1.0                                                 #  
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
       """
print(bcolors.FAIL + auth + bcolors.RESET)


def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Specify interface on which to sniff packets")
    arguments = parser.parse_args()
    return arguments.interface

def sniff(iface):
    scapy.sniff(iface=iface, store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print(bcolors.OK + "[+] Http Request >> " + str(packet[http.HTTPRequest].Host) + str(packet[http.HTTPRequest].Path) + bcolors.RESET)
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            print(bcolors.WARNING + "\n[+] Possible password/username >> " + str(load) +"\n")
            
iface = get_interface()
print(bcolors.WARNING + "[~]Monitoring the packets for the sensitive information[~]" + bcolors.RESET)
sniff(iface)

