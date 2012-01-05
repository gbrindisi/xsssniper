#/usr/bin/env python

from urllib import urlencode

class Result:
    """
    A Result represent a successful XSS injection.
    Used to clean the Scanner and handle printing
    """

    def __init__(self, target, injected_param, payload, injectiontype):
        self.target = target
        self.first_param = injected_param
        self.first_pl = payload
        
        self.injections = { injected_param: [[injectiontype, payload]] }

    def printResult(self):
        print "\n[!] Target:\t%s" % self.target.getAbsoluteUrl()
        print "    Method:\t%s" % self.target.method
        print "    Query String:\t%s" % urlencode(self.target.params)
        for param, inj in self.injections.iteritems():
            print "\t[%sx] Param:\t%s" % (len(inj), param)
            for i in inj:
                print "\t     Type:\t%s - %s" % (i[0][0], i[0][1]) 
       
        return True

    def merge(self, other):
        if self.target ==  other.target:
            for param, value in other.injections.iteritems():
                if self.injections.has_key(param):
                    self.injections[param].append(value)
                else:
                    self.injections[param] = value
            return True
        return False           
