#/usr/bin/python

try:
    from michanize import Request, urlopen, URLError, HTTPError,ProxyHandler, build_opener, install_opener, Browser
except ImportError:
    print "\n[X] Please install mechanize module:"
    print "    http://wwwsearch.sourceforge.net/mechanize/\n"
    exit()
try:
    import lxml.etree as ET
except ImportError:
    print "\n[X] Please install lxml module:"
    print "    http://lxml.de/\n"
    exit()

import os
import re

from core.target import Target
from core.payload import Payload
from core.result import Result

class Scanner:
    def __init__(self, payload = None, target = None):
        self.payloads = [] 
        if payload is None:
            # Uber dirty trick to get payloads.xml path
            self.parsePayloadsFromFile(os.path.dirname(os.path.realpath(__file__))[:-4]+ "lib/payloads.xml")
        else:
            self.payloads.append(payload)

        self.targets = [] if target is None else [target]
        self.config = {}
        self.results = []

    def addOption(self, key, value):
        if key in self.config:
            del self.config[key]
        self.config[key] = value

    def getOption(self, key):
        if key in self.config:
            return self.config[key] 
        else:
            return None

    def addResult(self, result):
        """
        Add a result to the scanner
        """
        self.results.append(result)

    def getResults(self):
        """
        Return the array of results
        """
        return self.results

    def printResults(self):
        """
        Print every result
        """
        for r in self.getResults():
            r.printResult()

    def getLoadedPayloads(self):
        """
        Return the array of loaded payloads
        """
        return self.payloads

    def addPayload(self, payload, check = None, description = None, reference = None):
        """
        Append a new payload to the array of loaded payloads
        """
        self.payloads.append(Payload(payload, check, description, reference))

    def parsePayloadsFromFile(self, file):
        """
        Parse an xml file for payloads and append 
        them to the array of loaded payloads
        """
        tree = ET.parse(file)
        document = tree.getroot()
        for elem in document:
            self.addPayload(
                elem.find('raw').text,
                elem.find('check').text,
                elem.find('description').text,
                elem.find('reference').text
            )

    def getLoadedTargets(self):
        """
        Return the array of loaded targets
        """
        return self.targets

    def addTarget(self, raw_url):
        """
        Append a new target to the array of loaded targets
        """
        self.targets.append(Target(raw_url))

    def crawlTarget(self, target):
        """
        Given a Target obj will parse it for links
        in the same domain and load them as targets in the scanner
        """
        br = Browser()
        print target.getBaseUrl()
        try: br.open(target.getBaseUrl())
        except HTTPError, e:
            print "[X] Error: %s on %s" % (e.code, url)
        except URLError, e:
            print "[X] Error: can't connect"
        else:
            # Find absolute link in the same domain or replative links
            links = br.links(url_regex="(^" + target.getBaseUrl() + ".)|(^/{1}.)")
            new_targets = []
            for link in links:
                # Some link parsing
                if link.url.startswith("http://http://"): link.url.replace("http://http://", "http://")
                if link.url.startswith("/"): link.url = target.getBaseUrl() +link.url
                new_targets.append(link.url)
            # Remove duplicate links
            new_targets = set(new_targets)
            print "[-] Found %s unique URLs" % len(new_targets)        
            for t in new_targets:
                self.addTarget(t)

    def start(self):         
        """
        Main method.
        It test every params in URL of every target against every loaded payload
        """
        if self.getOption('crawl') is not None:
            print "[+] Crawling for links..."
            self.crawlTarget(self.getLoadedTargets()[0])
        print "\n[+] Start scanning...\n"

        for c, target in enumerate(self.getLoadedTargets()):
            print "[-] Testing %s/%s" % (c+1, len(self.getLoadedTargets()))

            if len(target.getParams()) == 0:
                # print "[X] No GET parameters to inject"
                continue

            for k, v in target.getParams().iteritems():
                for pl in self.getLoadedPayloads():
                    url = target.getPayloadedUrl(k, pl.getPayload())
                    if self.getOption('http-proxy') is not None:
                        proxy = ProxyHandler({'http': self.getOption('http-proxy')})
                        opener = build_opener(proxy)
                        install_opener(opener)
                    req = Request(url)
                    # TODO: A verbose option, for now print only when you found something
                    # print "[-] Testing:\t%s" % pl.getPayload()
                    # print "    Param:\t%s" % k
                    # print "    Url:\t%s" % url
                    try: response = urlopen(req)
                    except HTTPError, e:
                        print "[X] Error: %s on %s" % (e.code, url)
                    except URLError, e:
                        print "[X] Error: can't connect"
                    else:
                        result = response.read()
                        if result.find(pl.getCheck()) != -1:
                            r = Result(url, k, pl, 0)
                            self.addResult(r)
                        elif result.find(pl.getCheck().lower()) != -1:
                            r = Result(url, k, pl, 2)
                            self.addResult(r)
                        elif result.find(pl.getCheck().upper()) != -1:
                            r = Result(url, k, pl, 1)
                            self.addResult(r)
                        else:
                            pass

        # And now the scan is complete
        print "\n    ... Done!"
        self.printResults()

