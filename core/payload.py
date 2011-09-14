#/usr/bin/python

class Payload:
    def __init__(self, payload, check = None, description = None, reference = None):
        self.payload = payload
        self.check = payload if check is None else check
        self.description = description
        self.reference =  reference           

    def getPayload(self):
        return self.payload

    def getCheck(self):
        return self.check  
        
    def getDescription(self):
        return self.description
        
    def getReference(self):
        return self.reference

