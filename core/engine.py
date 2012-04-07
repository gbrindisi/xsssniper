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
from core.domscanner import DOMScanner
from core.packages.clint.textui import colored, progress

class Engine:
    def __init__(self, target = None):
        self.targets = []
        if target is not None: self.targets.append(target)
        self.config = {}
        self.results = []
        # Container for js analysis
        self.javascript = []

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
    
    def _compactTargets(self):
        self.targets = list(set(self.targets))
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

        # Print javascript analysis
        if self.getOption("dom") and len(self.javascript) == 0:
            print "\n[X] No DOM XSS Found :("
        elif self.getOption("dom"):
            print "\n[!] Found possible dom xss in %s javascripts" % len(self.javascript)
            for js in self.javascript:
                js.printResult()

    def _crawlTarget(self):
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
        errors = {}
        for c in crawlers:
            # results
            for r in c.results:
                results.append(r)
            # errors
            for ek, ev in c.errors.iteritems():
                if errors.has_key(ek):
                    errors[ek] += ev
                else:
                    errors[ek] = ev

        results = set(results)
        
        if errors:
            print "[X] Crawl Errors:"
            for ek, ev in errors.iteritems():
                print "    %s times %s" % (len(ev), ek)

        print "[-] Found %s unique targets." % len(results)
        

        # Add targets
        for t in results:
            self.targets.append(t)

    def _crawlForms(self):
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
        errors = {}
        for c in crawlers:
            # results
            for r in c.results:
                results.append(r)
            # errors
            for ek, ev in c.errors.iteritems():
                if errors.has_key(ek):
                    errors[ek] += ev
                else:
                    errors[ek] = ev

        results = set(results)

        if errors:
            print "[X] Crawl Errors:"
            for ek, ev in errors.iteritems():
                print "    %s times %s" % (len(ev), ek)

        print "[-] Found %s unique forms." % len(results)

        # Add targets
        for t in results:
            self.targets.append(t)

    def _scanTargets(self):
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
        
        # Harvest results
        results = []
        errors = {}
        for t in threads:
            for r in t.results:
                results.append(r)
            # errors
            for ek, ev in t.errors.iteritems():
                if errors.has_key(ek):
                    errors[ek] += ev
                else:
                    errors[ek] = ev

        # Add results to engine
        for r in results:
            self.results.append(r)

        if errors:
            print "[X] Scan Errors:"
            for ek, ev in errors.iteritems():
                print "    %s times %s" % (len(ev), ek)

    def _scanDOMTargets(self):
        print "\n[+] Start DOM scanning (%s threads)" % self.getOption('threads')
        
        threads = []
        queue = self._getTargetsQueue()
        for i in range(min(self.getOption('threads'), len(self.targets))):
            t = DOMScanner(self, queue)
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
        
        # Harvest results
        javascript = []
        errors = {}
        for t in threads:
            for r in t.javascript:
                javascript.append(r)
            # errors
            for ek, ev in t.errors.iteritems():
                if errors.has_key(ek):
                    errors[ek] += ev
                else:
                    errors[ek] = ev

        # Add results to engine
        for r in javascript:
            if len(r.sources) > 0 | len(r.sinks) > 0:
                self.javascript.append(r)

        if errors:
            print "[X] Scan Errors:"
            for ek, ev in errors.iteritems():
                print "    %s times %s" % (len(ev), ek)
       

    def start(self):         
        """
        Eventually crawl links and form, then
        spawn threads to handle the scanning
        """
        start = time.time()

        if self.getOption('crawl'):
            self._crawlTarget()

        if self.getOption('forms'):
            self._crawlForms()

        self._compactTargets()    
       
        self._scanTargets()
        
        if self.getOption('dom'):
            self._scanDOMTargets()

        print "[-] Scan completed in %s seconds" % (time.time() - start)
                        
        print "[+] Processing results..."

        self._compactResults()
        self.printResults()
        
        return True
        
