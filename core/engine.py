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
from core.scanner import Scanner

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

    def _compactResults(self):
        temp_results = []
        for result in self.results:
            found = False
            for temp_result in temp_results:
                if temp_result.target == result.target:
                    temp_result.merge(result)
                    found = True
                    break
            if not found:
                temp_results.append(result)

        self.results = temp_results
        return True

    def addOption(self, key, value):
        if key in self.config:
            del self.config[key]
        self.config[key] = value

    def getOption(self, key):
        if key in self.config:
            return self.config[key] 
        else:
            return None

    def printResults(self):
        """
        Print every result
        """
        if len(self.results) == 0:
            print "\n[X] No XSS Found :("
        else:
            print "\n[!] Found XSS Injection points in %s targets" % len(self.results)
            for r in self.results:
                r.printResult()

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
        for i in range(min(self.getOption('threads'), len(self.targets))):
            t = Scanner(self, queue)
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

        # Harvest results
        results = []
        for t in threads:
            for r in t.results:
                results.append(r)

        # Add results to engine
        for r in results:
            self.results.append(r)
        
        print "[+] Processing results..."
        if self._compactResults():
            self.printResults()
            return True
        else:
            return False
