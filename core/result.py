#/usr/bin/env python

class Result:
    """
    A Result represent a successful XSS injection.
    Used to clean the Scanner and handle printing
    """
    def __init__(self, url, param, method, taint, injectiontype):
        self.url = url
        self.param = param
        self.method = method
        self.taint = taint
        self.injectiontype = injectiontype

    def printResult(self):
        print "\n[!] URL:\t%s" % self.url
        print "    Type:\t%s" % self.injectiontype[1]
        print "    Param:\t%s" % self.param
        print "    Method:\t%s" % self.method
        #print "    Taint:\t%s" % self.taint
