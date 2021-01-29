#!/usr/bin/python3
import sys
import time
from datetime import datetime
import argparse
import netaddr
from scapy.all import *
conf.verb = 0 #Turn scapy verbose mode off


class Scanner:

    def __init__(self, hosts):
        self.target = list(netaddr.IPNetwork(hosts))
        

    def ping(self, host, pmethod="ICMP"):
        host = str(host)
        if pmethod == "ICMP":
            packet = IP(dst=host)/ICMP()
            response = sr1(packet, retry=3, timeout=2)
            if response is not None:
                #echo-reply (type:0 - code:0)
                if response["ICMP"].type == 0:
                    return True
                #destination unreachable (type:3) 
                else:
                    return False    
            return False

        if pmethod == "UDP":
            packet = IP(dst=host)/UDP(dport=40)
            response = sr1(packet, retry=3, timeout=3)
            if response is not None:
                #destination unreachable (type:3) - port unreachable (code:3)
                if response["ICMP"].type == 3 and response["ICMP"].code == 3:
                    return True
                #destination unreachable (type:3) - host unreachable (code:1)
                if response["ICMP"].type == 3 and response["ICMP"].code == 1:
                    return False
            return False
            
        if pmethod == "TCP":
            packet = IP(dst=host)/TCP(dport=80, flags="S")
            response = sr1(packet, retry=3, timeout=3)
            if response is not None:
                if "ICMP" in response:
                    return False
                else:
                    return True
            else:
                return False

        if pmethod == "ARP":
            packet = Ether(dst="ff:ff:ff:ff:ff")/ARP(pdst=host)
            response = srp(packet, timeout=5)
            if len(response[0]) == 0:
                return False
            return True


def main():
    parser = argparse.ArgumentParser(prog="scanner",
                                    usage="%(prog)s [options] ip/ip range.",
                                    description="A simple network scanner tool.")
    parser.add_argument("ip", help="IP or IP range to scan.")
    parser.add_argument("-Pi", action="store_true", help="Discovery/ping host(s) using ICMP.")
    parser.add_argument("-Pt", action="store_true", help="Discovery/ping host(s) using TCP SYN.")
    parser.add_argument("-Pu", action="store_true", help="Discovery/ping host(s) using UDP.")
    parser.add_argument("-Pa", action="store_true", help="Discovery/ping host(s) using ARP.")

    if len(sys.argv) <= 2:
        parser.print_help()
        parser.exit(1)

    args = parser.parse_args()
    s = Scanner(args.ip)
    total_host = 0
    host_up = 0
    host_down = 0
    
    start_time = datetime.now()
    print(f"Starting scan at {start_time}")

    try:
        if args.Pi:
            for host in s.target:
                if s.ping(host):
                    print(f"[+] Host {host} is up.")
                    host_up += 1
                else:
                    print(f"[-] Host {host} is down.")
                    host_down += 1
                total_host += 1
            elapsed_time = datetime.now() - start_time
            print(f"[*] Scanned {total_host} host: {host_up} host up and {host_down} host down, in {elapsed_time} seconds.")
        
        if args.Pu:
            for host in s.target:
                if s.ping(host, "UDP"):
                    print(f"[+] Host {host} is up.")
                    host_up += 1
                else:
                    print(f"[-] Host {host} is down.")
                    host_down += 1
                total_host += 1
            print(f"[*] Scanned {total_host} host: {host_up} host up and {host_down} host down.")
        
        if args.Pt:
            for host in s.target:
                if s.ping(host, "TCP"):
                    print(f"[+] Host {host} is up.")
                    host_up += 1
                else:
                    print(f"[-] Host {host} is down.")
                    host_down += 1
                total_host += 1
            print(f"[*] Scanned {total_host} host: {host_up} host up and {host_down} host down.")
        
        if args.Pa:
            for host in s.target:
                if s.ping(host, "ARP"):
                    print(f"[+] Host {host} is up.")
                    host_up += 1
                else:
                    print(f"[-] Host {host} is down.")
                    host_down += 1
                total_host += 1
            print(f"[*] Scanned {total_host} host: {host_up} host up and {host_down} host down.")
    except KeyboardInterrupt:
        print("[!] Script terminated. Good bye!!")
        sys.exit(1)


if __name__ == "__main__":
    main()
