#/usr/bin/env python

class Javascript:
    """
    Used to represent a Javascript file and the result o it's
    analysis
    """

    def __init__(self, link, body, is_embedded=False):
        self.link = link
        self.body = body
        self.is_embedded = is_embedded

        self.sources = []
        self.sinks = []

    def addSource(self, line, pattern):
        s = (line, pattern)
        self.sources.append(s)

    def addSink(self, line, pattern):
        s = (line, pattern)
        self.sinks.append(s)
    
    def printResult(self):
        if len(self.sources) > 0 | len(self.sinks) > 0:
            print "\n[+] Javascript:\t%s" % self.link
            if self.is_embedded:
                print "[+]        \t(embedded)"
            print "[-] Possible Sources:\t %s" % len(self.sources)
            for s in self.sources:
                print "\t[%s] - %s" % (s[0], s[1])

            print "[-] Possible Sinks:\t %s" % len(self.sinks)
            for s in self.sinks:
                print "\t[%s] - %s" % (s[0], s[1])
            
