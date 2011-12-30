#! /usr/bin/env python

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
import sys

from core.target import Target
from core.result import Result
from core.crawler import Crawler
from core.constants import USER_AGENTS

class Engine:
    def __init__(self, target = None):
        self.targets = []
        if target is not None: self.targets.append(target)
        self.config = {}
        self.results = []

    def _getTargetsQueue(self):
        queue = Queue.Queue()
        for t in self.targets:
            queue.put(t)
        return queue

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
        self.targets.append(Target(raw_url, method, data))

    def crawlTarget(self):
        print "[+] Crawling links..."

        # Build a queue and start crawlers 
        queue = self._getTargetsQueue()
        crawlers = []
        for i in range(min(self.getOption('threads'), len(self.targets))):
            c = Crawler(self, queue, crawl_links=True)
            c.setDaemon(True)
            crawlers.append(c)
            c.start()
      
        # Little hack to kill threads on SIGINT
        while True:
            try:
                if queue.empty() is True:
                    break
                sys.stdout.write("\r    Remaining targets: %s" % queue.qsize())
                sys.stdout.flush()
            except KeyboardInterrupt:
                print "[X] Interrupt! Killing threads..."
                queue = Queue.Queue()
                break
        
        queue.join()

        # Harvest results
        results = []
        for c in crawlers:
            for r in c.results:
                results.append(r)

        results = set(results)

        print "[-] Found %s unique targets." % len(results)

        # Add targets
        for t in results:
            self.targets.append(t)

    def crawlForms(self):
        print "[+] Crawling for forms..."
         
        queue = self._getTargetsQueue()
        crawlers = []
        for i in range(min(self.getOption('threads'), len(self.targets))):
            c = Crawler(self, queue, crawl_forms=True)
            c.setDaemon(True)
            crawlers.append(c)
            c.start()
      
        # Little hack to kill threads on SIGINT
        while True:
            try:
                if queue.empty() is True:
                    break
                sys.stdout.write("\r    Remaining targets: %s" % queue.qsize())
                sys.stdout.flush()
            except KeyboardInterrupt:
                print "[X] Interrupt! Killing threads..."
                queue = Queue.Queue()
                break
        
        queue.join()

        # Harvest results
        results = []
        for c in crawlers:
            for r in c.results:
                results.append(r)

        results = set(results)

        print "[-] Found %s unique forms." % len(results)

        # Add targets
        for t in results:
            self.targets.append(t)

    def start(self):         
        """
        Eventually crawl links and form, then
        spawn threads to handle the scanning
        """
        if self.getOption('crawl') is not None:
            self.crawlTarget()

        if self.getOption('forms') is not None:
            self.crawlForms()
        
        start = time.time()
        print "\n[+] Start scanning (%s threads)" % self.getOption('threads')
        
        threads = []
        queue = self._getTargetsQueue()
        for i in range(self.getOption('threads')):
            t = ScannerThread(queue, self)
            t.setDaemon(True)
            threads.append(t)
            t.start()
      
        # Little hack to kill threads on SIGINT
        while True:
            try:
                if queue.empty() is True:
                    print "\n"
                    break
                sys.stdout.write("\r    Remaining urls: %s" % queue.qsize())
                sys.stdout.flush()
            except KeyboardInterrupt:
                print "[X] Interrupt! Killing threads..."
                queue = Queue.Queue()
                break
        
        queue.join()
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
                target = self.queue.get(timeout=1)
            except:
                try:
                    self.queue.task_done()
                except ValueError:
                    # Can't handle this
                    pass
            else:
                # No GET/POST parameters? Skip to next url 
                if len(target.params) == 0:
                    # print "[X] No paramaters to inject"
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
                    # Some headers
                    if self.scannerengine.getOption('ua') is not None:
                        if self.scannerengine.getOption('ua') is "RANDOM":
                            headers = {'User-Agent': random.choice(USER_AGENTS)}
                        else:
                            headers = {'User-Agent': self.scannerengine.getOption('ua')}
                    # Build the request
                    req = Request(url, data, headers)
                    try:
                        to = 10 if self.scannerengine.getOption('http-proxy') is None else 20
                        response = urlopen(req, timeout=to)
                        print response.read()
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
                try:                
                    self.queue.task_done()
                except ValueError:
                    pass
