#/usr/bin/env python

class Result:
    """
    A Result represent a successful XSS injection.
    Used to clean the Scanner and handle printing
    """

    def __init__(self, target, injected_param, taint, injectiontype):
        self.target = target
        self.injections = [(injected_param, taint, injectiontype)]

    def printResult(self):
        print "\n[!] %s Injections:\t%s" % (len(self.injections), self.target.getAbsoluteUrl())
        print "    Method:\t%s" % self.target.method
        for k, inj in enumerate(self.injections):
            print "\t[%s] Param:\t%s" % (k+1, inj[0])
            print "\t     Type:\t%s" % inj[2][1]
       
        return True

    def merge(self, result):
        if self.target ==  result.target:
            for inj in result.injections:
                self.injections.append(inj)
            return True
        return False
