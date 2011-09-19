class Result:
    """
    A Result represent a successful XSS injection.
    Used to clean the Scanner and handle printing
    """
    def __init__(self, url, param, method, payload, mode):
        """
        Mode: 0 normal check
              1 uppercase check
              2 lowercase check
        """
        self.url = url
        self.param = param
        self.method = method
        self.payload = payload
        if mode is 1:
            self.mode = mode
            self.check = self.payload.check.uppercase()
        elif mode is 2:
            self.mode = mode
            self.check = self.payload.check.lowercase()
        else:
            self.mode = 0
            self.check = self.payload.check

    def printResult(self):
        print "\n[!] XSS Found:\t%s" % self.url
        print "    Method:\t%s" % self.method
        print "    Param:\t%s" % self.param
        print "    Payload:\t%s" % self.payload.payload
        print "    Check:\t%s" % self.check
        print "    Desc:\t%s" % self.payload.description
        print "    Reference:\t%s" % self.payload.reference
