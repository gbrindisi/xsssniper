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

version 0.2                                     Gianluca Brindisi <g@brindi.si>
                                      https://bitbucket.org/gbrindisi/xsssniper

 -----------------------------------------------------------------------------
| Scanning targets without prior mutual consent is illegal. It is the end     |
| user's responsibility to obey all applicable local, state and federal laws. |
| Authors assume no liability and are not responsible for any misuse or       | 
| damage caused by this program.                                              |
 -----------------------------------------------------------------------------
    """

def main():
    banner()
    usage = "usage: %prog [options]"

    parser = OptionParser(usage=usage)
    parser.add_option("-u", "--url", dest="url", help="target URL")
    parser.add_option("-p", "--payload", dest="payload", help="payload to inject. If the payload is not specified standard payloads from lib/payloads.xml will be used")
    parser.add_option("-c", "--check", dest="check", help="payload artefact to search in response")
    parser.add_option("--post", dest="post", default=False, action="store_true", help="try a post request to target url")
    parser.add_option("--data", dest="post_data", help="posta data to use")
    parser.add_option("--threads", dest="threads", default=1, help="number of threads")
    parser.add_option("--http-proxy", dest="http_proxy", help="scan behind given proxy (format: 127.0.0.1:80)")
    parser.add_option("--tor", dest="tor", default=False, action="store_true", help="scan behind default Tor")
    parser.add_option("--crawl", dest="crawl", default=False, action="store_true", help="crawl target url for other links to test")
    (options, args) = parser.parse_args()
    if options.url is None: 
        parser.print_help() 
        exit()

    # Build a first target
    if options.post is True:
        if options.post_data is not None:
            t = Target(options.url, method = 'POST', data = options.post_data)
        else:
            print "[X] No POST data specified: use --data"
            exit()
    else:
        t = Target(options.url)



    # Build a scanner
    if options.payload is not None:
        p = Payload(options.payload, options.check)
        s = Scanner(p, t)
    else:
        s = Scanner(target = t)

    # Lets parse options for some proxy setting
    if options.http_proxy is not None and options.tor is True:
        print "[X] Yo dawg! I heard you like proxies so i put a proxy in your proxy..."
        print "    (no --tor and --http-proxy together please!)"
        exit()
    elif options.tor is False and options.http_proxy is not None:
        s.addOption("http-proxy", options.http_proxy)
    elif options.tor is True:
        s.addOption("http-proxy", "127.0.0.1:8118")

    # Do you want to crawl?
    if options.crawl is True:
        s.addOption("crawl", True)

    # How many threads?
    s.addOption("threads", int(options.threads))

    # Start the scanning
    s.start()

if __name__ == '__main__':
    main()
