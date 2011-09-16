class Result:
    """
    A Result represent a successful XSS injection.
    Used to clean the Scanner and handle printing
    """
    def __init__(self, url, param, payload, mode):
        """
        Mode: 0 normal check
              1 uppercase check
              2 lowercase check
        """
        self.url = url
        self.param = param
        self.payload = payload
        if mode is 1:
            self.mode = mode
            self.check = self.payload.getCheck().uppercase()
        elif mode is 2:
            self.mode = mode
            self.check = self.payload.getCheck().lowercase()
        else:
            self.mode = 0
            self.check = self.payload.getCheck()

    def printResult(self):
        print "\n[!] XSS Found:\t%s" % self.url
        print "    Param:\t%s" % self.param
        print "    Payload:\t%s" % self.payload.getPayload()
        print "    Check:\t%s" % self.check
        print "    Desc:\t%s" % self.payload.getDescription()
        print "    Reference:\t%s" % self.payload.getReference()
