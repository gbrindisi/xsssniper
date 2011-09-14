#/usr/bin/python

import os
from optparse import OptionParser

from core.target import Target
from core.payload import Payload
from core.scanner import Scanner

def banner():
    print """
db    db .d8888. .d8888.      .d8888. d8b   db d888888b d8888b. d88888b d8888b. 
`8b  d8' 88'  YP 88'  YP      88'  YP 888o  88   `88'   88  `8D 88'     88  `8D 
 `8bd8'  `8bo.   `8bo.        `8bo.   88V8o 88    88    88oodD' 88ooooo 88oobY' 
 .dPYb.    `Y8b.   `Y8b.        `Y8b. 88 V8o88    88    88~~~   88~~~~~ 88`8b   
.8P  Y8. db   8D db   8D      db   8D 88  V888   .88.   88      88.     88 `88. 
YP    YP `8888Y' `8888Y'      `8888Y' VP   V8P Y888888P 88      Y88888P 88   YD

version 0.1                                                          @gbrindisi
    """

def main():
    banner()
    usage = "usage: %prog [options]"
    parser = OptionParser(usage=usage)
    parser.add_option("-u", "--url", dest="url", help="target URL")
    parser.add_option("-p", "--payload", dest="payload", help="payload to inject")
    parser.add_option("-c", "--check", dest="check", help="payload artefact to search in response")
    (options, args) = parser.parse_args()
    if options.url is None: 
        parser.print_help() 
        exit()

    t = Target(options.url)
    
    if options.payload is not None:
        p = Payload(options.payload, options.check)
        s = Scanner(p)
    else:
        s = Scanner()

    print "[-] Target:\t %s" % t.getFullUrl()

    s.testTarget(t)

if __name__ == '__main__':
    main()
