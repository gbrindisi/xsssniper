#/usr/bin/python

try:
    from mechanize import Request, urlopen, URLError, HTTPError,ProxyHandler, build_opener, install_opener, Browser
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
import Queue
import threading
import time

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

        # Initialize the queue of targets
        self.targets = Queue.Queue()
        if target is not None: self.targets.put(target)

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

    def printResults(self):
        """
        Print every result
        """
        if len(self.results) == 0:
            print "\n[X] No XSS Found :("
        else:
            for r in self.results:
                r.printResult()

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

    def addTarget(self, raw_url, method = 'GET', data = None):
        """
        Append a new target to the array of loaded targets
        """
        self.targets.put(Target(raw_url, method, data))

    def crawlTarget(self, target):
        """
        Given a Target obj will parse it for links
        in the same domain and load them as targets in the scanner
        """
        print "[+] Crawling for links..."
        br = Browser()
        try: br.open(target.getAbsoluteUrl())
        except HTTPError, e:
            print "[X] Error: %s on %s" % (e.code, target.getAbsoluteUrl())
            print "    Crawl aborted"
        except URLError, e:
            print "[X] Error: can't connect"
            print "    Crawl aborted"
        else:
            # Find absolute link in the same domain or replative links
            links = br.links(url_regex="(^" + target.getBaseUrl() + ".)|(^/{1}.)")
            new_targets = []
            for link in links:
                # Some link parsing
                if link.url.startswith("http://http://"): link.url.replace("http://http://", "http://")
                if link.url.startswith("/"): link.url = target.getBaseUrl() + link.url
                new_targets.append(link.url)
            # Remove duplicate links
            new_targets = set(new_targets)
            print "[-] Found %s unique URLs" % len(new_targets)        
            for t in new_targets:
                self.addTarget(t)

    def crawlForms(self, targets):
        """
        Crawl targets for forms
        target must be a list
        """
        print "\n[+] Crawling for forms..."
        br = Browser()
        new_targets = []
        for t in targets:
            try: br.open(t.getAbsoluteUrl())
            except HTTPError, e:
                print "[X] Error: %s on %s" % (e.code, t.getAbsoluteUrl())
            except URLError, e:
                print "[X] Error: can't connect"
            else:
                forms = br.forms()
                for form in forms:
                    form_data = form.click_request_data()
                    new_targets.append([form_data[0], form_data[1]])
        # Now remove duplicates:
        new_targets = dict((x[0], x) for x in new_targets).values()
        print "[-] Found %s unique forms" % len(new_targets)
        for nt in new_targets:
            self.addTarget(nt[0], method = 'POST', data = nt[1])

    def start(self):         
        """
        Main method.
        It test every params in URL of every target against every loaded payload
        """

        if self.getOption('crawl') is not None:
            self.crawlTarget(self.targets.get())

        if self.getOption('forms') is not None:
            self.crawlForms([self.targets.get()])

        start = time.time()
        print "\n[+] Start scanning (%s threads)" % self.getOption('threads')
        for i in range(self.getOption('threads')):
            t = ScannerThread(self.targets, self)
            t.setDaemon(True)
            t.start()

        self.targets.join()
        print "[-] Scan completed in %s seconds" % (time.time() - start)
        self.printResults()

class ScannerThread(threading.Thread):
    def __init__(self, queue, scannerengine):
        threading.Thread.__init__(self)
        self.queue = queue
        self.scannerengine = scannerengine

    def run(self):
        while True:
            try:
                target = self.queue.get(block=False)
            
            # If queue is empty or whatever
            except:
                try:
                    self.queue.task_done()
                except ValueError:
                    # Can't handle this
                    pass

            # Otherwise...
            else:
                # No GET/POST parameters? Skip to next url
                if len(target.params) == 0:
                    print "[X] No paramaters to inject"
                    self.queue.task_done()
                    continue

                # Check every parameter
                for k, v in target.params.iteritems():
                    for pl in self.scannerengine.payloads:
                        url, data = target.getPayloadedUrl(k, pl.payload)
                        if self.scannerengine.getOption('http-proxy') is not None:
                            proxy = ProxyHandler({'http': self.getOption('http-proxy')})
                            opener = build_opener(proxy)
                            install_opener(opener)
                        req = Request(url, data)
                        # TODO: A verbose option, for now print only when you find something
                        # print "[-] Testing:\t%s" % pl.getPayload()
                        # print "    Param:\t%s" % k
                        # print "    Url:\t%s" % url
                        try: response = urlopen(req)
                        except HTTPError, e:
                            print "[X] Error: %s on %s" % (e.code, url)
                            continue
                        except URLError, e:
                            print "[X] Error: can't connect"
                            continue
                        else:
                            result = response.read()
                            if result.find(pl.check) != -1:
                                r = Result(url, k, target.method, pl, 0)
                                self.scannerengine.addResult(r)
                            elif result.find(pl.check.lower()) != -1:
                                r = Result(url, k, target.method, pl, 2)
                                self.scannerengine.addResult(r)
                            elif result.find(pl.check.upper()) != -1:
                                r = Result(url, k, target.method, pl, 1)
                                self.scannerengine.addResult(r)
                            else:
                                pass
                
                # Scan complete                
                self.queue.task_done()


