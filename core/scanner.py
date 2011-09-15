#/usr/bin/python

#from urllib2 import Request, urlopen, URLError, HTTPError
from mechanize import Request, urlopen, URLError, HTTPError
import lxml.etree as ET
import os

from core.target import Target
from core.payload import Payload

class Scanner:
    def __init__(self, payload = None, target = None):
        self.payloads = [] 
        if payload is None:
            # Uber dirty trick to get payloads.xml path
            self.parsePayloadsFromFile(os.path.dirname(os.path.realpath(__file__))[:-4]+ "lib/payloads.xml")
        else:
            self.payloads.append(payload)

        self.targets = [] if target is None else [target]

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

    def start(self):         
        """
        Main method.
        It test every params in URL of every target against every loaded payload
        """
        for target in self.getLoadedTargets():
            for k, v in target.getParams().iteritems():
                for pl in self.getLoadedPayloads():
                    url = target.getPayloadedUrl(k, pl.getPayload())
                    req = Request(url)
                    print "\n[-] Testing:\t%s" % pl.getPayload()
                    print "    Param:\t%s" % k
                    print "    Url:\t%s" % url
                    try: response = urlopen(req)
                    except HTTPError, e:
                        print "[X] Error: %s on %s" % (e.code, url)
                    except URLError, e:
                        print "[X] Error: can't connect"
                    else:
                        result = response.read()
                        if result.find(pl.getCheck()) != -1:
                            print "\n[!] XSS Found:\t%s" % url
                            print "    Payload:\t%s" % pl.getPayload()
                            print "    Check:\t%s" % pl.getCheck()
                            print "    Desc:\t%s" % pl.getDescription()
                            print "    Reference:\t%s" % pl.getReference()
                        elif result.find(pl.getCheck().lower()) != -1:
                            print "\n[!] XSS Found:\t%s" % url
                            print "    Payload:\t%s" % pl.getPayload()
                            print "    Check:\t%s" % pl.getCheck().lower()
                            print "    Desc:\t%s" % pl.getDescription()
                            print "    Reference:\t%s" % pl.getReference()
                        elif result.find(pl.getCheck().upper()) != -1:
                            print "\n[!] XSS Found:\t%s" % url
                            print "    Payload:\t%s" % pl.getPayload()
                            print "    Check:\t%s" % pl.getCheck().upper()
                            print "    Desc:\t%s" % pl.getDescription()
                            print "    Reference:\t%s" % pl.getReference()
                        else:
                            print "    Nope :("

