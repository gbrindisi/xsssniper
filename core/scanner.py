#/usr/bin/env python

try:
    from mechanize import Request, urlopen, URLError, HTTPError,ProxyHandler, build_opener, install_opener, Browser
except ImportError:
    print "\n[X] Please install mechanize module:"
    print "    http://wwwsearch.sourceforge.net/mechanize/\n"
    exit()

import os
import re
import Queue
import threading
import time
import random
import string

from core.target import Target
from core.result import Result

class Scanner:
    def __init__(self, target = None):
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
            print "\n[!] Found %s XSS Injection points" % len(self.results)
            for r in self.results:
                r.printResult()

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
        if self.getOption('http-proxy') is not None:
            br.set_proxies({'http': self.getOption('http-proxy')})
        try: br.open(target.getAbsoluteUrl())
        except HTTPError, e:
            print "[X] Error: %s on %s" % (e.code, target.getAbsoluteUrl())
            print "    Crawl aborted"
            exit()
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
        if self.getOption('http-proxy') is not None:
            br.set_proxies({'http': self.getOption('http-proxy')})
        for t in targets:
            try: br.open(t.getAbsoluteUrl())
            except HTTPError, e:
                print "[X] Error: %s on %s" % (e.code, t.getAbsoluteUrl())
                print "    Crawl aborted"
                exit()
            except URLError, e:
                print "[X] Error: can't connect"
                print "    Crawl aborted"
                exit()
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
        Eventually crawl links and form, then
        spawn threads to handle the scanning
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

    def processResponse(self, response, seed):
        """
        Given a response object it search and return XSS injection.

        How it works: we parse the response sequentially
        looking for the seed while keeping
        a state of the current position to determine if we have
        a valid injection and where.

        This is based on ratproxy XSS scanning technique so
        all the props to @lcamtuf for this.
        """
        htmlstate = 0
        htmlurl = 0
        index = 0
        result = []

        # Building the taint and the response
        # I want everything lowercase because I don't want to handle 
        # cases when the payload is upper/lowercased by the webserver
        seed_len = len(seed)
        taint = "{0}:{0} {0}=-->{0}\"{0}>{0}'{0}>{0}+{0}<{0}>".format(seed)
        response = response.read().lower()

        # Now start the scanning
        # htmlstate legend:
        # - 1 index is in tag
        # - 2 index is inside double quotes
        # - 4 index is inside single quotes
        # - 8 index is inside html comment
        # - 16 index is inside cdata
        while index <= len(response)-1:
            # Exit cases for a match against the taint
            # If conditions are a little messy...
            # TODO: utf-7 xss
            if response[index:index+seed_len] == seed:
                # XSS found in tag
                # <tag foo=bar onload=...>
                # type 1
                if htmlstate == 1 and response[index+seed_len:index+seed_len+seed_len+1] == " " + seed + "=":
                    index = index + seed_len
                    result.append([1, "In tag: <tag foo=bar onload=...>"])
                    continue

                # XSS found in url
                # <tag src=foo:bar ...>
                # type 2
                if htmlurl and response[index+seed_len:index+seed_len+seed_len+1] == ":" + seed:
                    index = index + seed_len
                    result.append([2, "In url: <tag src=foo:bar ...>"])
                    continue

                # XSS found freely in response
                # <tag><script>...
                # type 3
                if htmlstate == 0 and response[index+seed_len:index+seed_len+seed_len+1] == "<" + seed:
                    index  = index + seed_len
                    result.append([3, "No filter evasion: <tag><script>..."])
                    continue

                # XSS found inside double quotes
                # <tag foo="bar"onload=...>
                # type 4
                if (htmlstate == 1 or htmlstate == 2) and response[index+seed_len:index+seed_len+seed_len] == "\"" + seed:
                    index = index + seed_len
                    result.append([4, "Inside double quotes: <tag foo=\"bar\"onload=...>"])
                    continue

                # XSS found inside single quotes
                # <tag foo='bar'onload=...>
                # type 5
                if (htmlstate == 1 or htmlstate == 4) and response[index+seed_len:index+seed_len+seed_len] == "'" + seed:
                    index  = index + seed_len
                    result.append([5, "Inside signle quotes: <tag foo='bar'onload=...>"])
                    continue

            else:
                # We are in a CDATA block
                if htmlstate == 0 and response[index:index+9] == "<![CDATA[":
                    htmlstate = 16
                    index = index + 9
                    continue

                if htmlstate == 16 and response[index:index+3] == "]]>":
                    htmlstate = 0
                    index = index + 3
                    continue

                # We are in a html comment
                if htmlstate == 0 and response[index:index+4] == "<!--":
                    htmlstate = 8
                    index = index + 4
                    continue

                if htmlstate == 8 and response[index:index+3] == "-->":
                    htmlstate = 0
                    index = index + 3
                    continue

                # We are in a tag
                if htmlstate == 0 and response[index] == "<" and (response[index+1] == "!" or response[index+1] == "?" or response[index+1].isalpha()):
                    htmlstate = 1
                    index = index + 1
                    continue

                if htmlstate == 1 and response[index] == ">":
                    htmlstate = 0
                    htmlurl = 0
                    index = index + 1
                    continue

                # We are inside a double quote
                if htmlstate == 1 and response[index] == '"' and response[index-1] == '=':
                    htmlstate = 2
                    index = index + 1
                    continue

                if (htmlstate == 1 or htmlstate == 2) and response[index] == '"':
                    htmlstate = 1
                    index = index + 1
                    continue

                # We are inside a single quote
                if htmlstate == 1 and response[index] == '\'' and response[index-1] == '=':
                    htmlstate = 4
                    index = index + 1
                    continue

                if (htmlstate == 1 or htmlstate == 4) and response[index] == '\'':
                    htmlstate = 1
                    index = index + 1
                    continue

                # We are inside an url
                if htmlstate == 1 and response[index-1] == " " and response[index:index+5] == "href=":
                    htmlurl = 1
                    index = index + 5 
                    continue

                if htmlstate == 1 and response[index-1] == " " and response[index:index+5] == "src=":
                    htmlurl = 1
                    index = index + 4
                    continue

                # In case the url isn't correctly closed
                if htmlurl == 1: 
                    htmlurl = 0

            # Move on
            index = index +1

        # End of response parsing
        return result
            
    def run(self):
        """ Main code of the thread """
        while True:
            try:
                target = self.queue.get(block=False)
            except:
                try:
                    self.queue.task_done()
                except ValueError:
                    # Can't handle this 
                    pass
            else:
                # No GET/POST parameters? Skip to next url 
                if len(target.params) == 0:
                    print "[X] No paramaters to inject"
                    self.queue.task_done()
                    continue

                # Check every parameter 
                for k, v in target.params.iteritems():
                    seed_len = 4
                    seed = ''.join(random.choice(string.ascii_letters + string.digits) for x in range(seed_len)).lower()
                    taint = "{0}:{0} {0}=-->{0}\"{0}>{0}'{0}>{0}+{0}<{0}>".format(seed)
                    url, data = target.getPayloadedUrl(k, taint)
                     
                    # In case of proxy 
                    if self.scannerengine.getOption('http-proxy') is not None:
                        proxy = ProxyHandler({'http': self.scannerengine.getOption('http-proxy')})
                        opener = build_opener(proxy)
                        install_opener(opener)
                    
                    # Build the request 
                    req = Request(url, data)
                    try: response = urlopen(req)
                    except HTTPError, e:
                        print "[X] Error: %s on %s" % (e.code, url)
                        continue
                    except URLError, e:
                        print "[X] Error: can't connect"
                        continue
                    else:
                        result = self.processResponse(response, seed)
                        for r in result:
                            self.scannerengine.addResult(Result(target.getPayloadedUrl(k, "")[0], k, target.method, taint, r))
                
                # Scan complete                
                self.queue.task_done()


