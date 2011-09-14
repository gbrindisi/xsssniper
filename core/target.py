#/usr/bin/python

from urlparse import urlparse
from urlparse import parse_qs
from urllib import urlencode

class Target:
    def __init__(self, raw_url):
        self.raw = raw_url

        tmp = urlparse(raw_url)
        
        self.scheme = tmp.scheme
        self.netloc = tmp.netloc
        self.path = tmp.path
        self.params = parse_qs(tmp.query, True)
    
    def getRawUrl(self):
        return self.raw
     
    def getUrl(self):
        """ 
        Build the absolute url.
        Normalize everything to http
        TODO: Enable networks urls
        """
        url = self.scheme if self.scheme != "" else "http"
        url += "://" + self.netloc + self.path
        return url

    def getFullUrl(self):
        return self.getUrl() + urlencode(self.params)
    
    def getParams(self):
        return self.params

    def getPayloadedUrl(self, target_key, payload):
        """
        Build an absolute url with the given payload in
        the specified parameter
        """
        new_params = self.getParams().copy()
        for k, v in new_params.iteritems():
            if k == target_key:
                del new_params[k]
                new_params[k] = v[0] + payload
        encoded_params = urlencode(new_params)

        return self.getUrl() + "?" + encoded_params

