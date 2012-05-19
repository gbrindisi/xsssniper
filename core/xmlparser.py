try:
    from lxml import etree
except ImportError:
    print "\n[X] Please install lxml module:"
    print "    http://lxml.de/\n"
    exit()

import os

class XMLparser():
    def __init__(self, path):
        try:
            f = open(path)
            self.xml = f.read()
            f.close()
            self.root = etree.XML(self.xml)
        except IOError, e:
            print "\n[X] Can't read xml: %s" % path
            print e
            #exit()


    def getNodes(self, nodename, parent=None):
        """
        Return a list of nodes from root or another 
        specified node
        """
        if parent is None:
            parent = self.root
        return [n for n in parent.iterfind(nodename)]


path = "../lib/whitelist.xml"
x = XMLparser(path)
for js in x.getNodes("javascript"):
    for h in x.getNodes("hash", parent=js):
        print h.text

