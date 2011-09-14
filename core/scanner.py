#/usr/bin/python

from urllib2 import Request, urlopen, URLError, HTTPError
import lxml.etree as ET
import os

from core.target import Target
from core.payload import Payload

class Scanner:
    def __init__(self, payload = None):
        self.payload = [] 
        if payload is None:
            # Uber dirty trick to get payloads.xml path
            self.parsePayloadsFromFile(os.path.dirname(os.path.realpath(__file__))[:-4]+ "lib/payloads.xml")
        else:
            self.payload.append(payload)

    def getPayloadObj(self):
        """
        Return the array of loaded payloads
        """
        return self.payload

    def addPayload(self, payload, check = None, description = None, reference = None):
        """
        Append a new payload to the array of loaded payloads
        """
        self.payload.append(Payload(payload, check, description, reference))

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

    
    def testTarget(self, target):         
        """
        Main method.
        It test every params in URL against every loaded payload
        """
        for k, v in target.getParams().iteritems():
            for pl in self.getPayloadObj():
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
                        """
                        user_answer = ''
                        while user_answer not in ('Y', 'N'):
                            user_answer =  raw_input("\n[?] Do you want to stop testing this parameter? [Y/N] ")
                        if user_answer == 'Y': break
                        """

