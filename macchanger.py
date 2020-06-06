#!/usr/bin/python3
import subprocess
import re
import random
import argparse
import sys

class Macchanger:

    def __init__(self, iface):
        self.iface = iface
        print(f"Current MAC: {self.get_mac_addr()}")


    def get_mac_addr(self):
        try:
            output = subprocess.check_output(["sudo","ifconfig",self.iface]).decode("utf-8")
        except Exception as err:
            print(f"Error occurs: {err}")
        mac_pattern = r"ether (?P<mac>([0-9a-f]{2}:){5}[0-9a-f]{2})"
        result = re.search(mac_pattern,output)
        if result:
            return result.group("mac")
        else:
            return "None"


    def mac_random(self):
        random_mac = f"00:{random.randint(10,99)}:{random.randint(10,99)}:{random.randint(10,99)}:{random.randint(10,99)}:{random.randint(10,99)}"
        return random_mac


    def change_mac_addr(self,new_mac="None"):
        if new_mac == "None":
            self.new_mac_addr = self.mac_random()
        else:
            self.new_mac_addr = new_mac
            
        try:
            subprocess.run(["sudo","ifconfig",self.iface,"down"], stdout=subprocess.DEVNULL)
            subprocess.run(["sudo","ifconfig",self.iface,"hw","ether",self.new_mac_addr], stdout=subprocess.DEVNULL)
            subprocess.run(["sudo","ifconfig",self.iface,"up"], stdout=subprocess.DEVNULL)
            subprocess.run(["sudo","/etc/init.d/networking","restart"], stdout=subprocess.DEVNULL)
        except Exception as err:
            print(f"Error occurs: {err}")
        print(f"New MAC: {self.new_mac_addr}")


def checkmac(mac_addr):
    mac_pattern = r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$"
    result = re.match(mac_pattern, mac_addr.lower())
    if result is not None:
        return True
    return False


def main():
    parser = argparse.ArgumentParser(prog="macchanger",
                                    usage="%(prog)s [options]",
                                    description="Tool to change your MAC address.")
    parser.add_argument("-i",
                        required=True,
                        metavar="interface",
                        help="interface to change MAC address (required).")
    parser.add_argument("-r", action="store_true", help="Assign a random MAC address (default).")
    parser.add_argument("-m",
                        metavar="MAC_ADDR",
                        help="Assign current MAC address with MAC_ADDR.")
    
    if len(sys.argv) == 1:
        parser.print_help()
        parser.exit(1)
        
    args = parser.parse_args()
 
    if args is not None:
        if args.m==None:
            mObj = Macchanger(args.i)
            mObj.change_mac_addr()
        else:
            if checkmac(args.m):
                mObj = Macchanger(args.i)
                mObj.change_mac_addr(args.m)
            else:
                print(f"{args.m} is not a valid MAC address.")


if __name__ == "__main__":
    main()
