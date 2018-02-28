# Blueborne CVE-2017-0785

This CVE and all the other BlueBorne CVEs are explained here: https://www.armis.com/blueborne/

This project was a proof of concept for a talk I gave in 2017. 

It simply performs a scan, prints out probably vulnerable hosts based on MACs and then runs the exploit on the target of your selection (if the device is actually vulnerable you will see a hex printout, if you run the exploit against a patched system nothing will return).

## Usage: 
  
  python bluebornescan.py

## References:

https://github.com/hook-s3c/blueborne-scanner

https://github.com/ojasookert/CVE-2017-0785


Pulled code from these two repos, polished it up a bit, and ported to python 3.

