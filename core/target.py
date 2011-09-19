#/usr/bin/python

from urlparse import urlparse
from urlparse import parse_qs
from urllib import urlencode

class Target:
    def __init__(self, raw_url):
        self.rawurl = raw_url

        self.scheme = urlparse(raw_url).scheme
        self.netloc = urlparse(raw_url).netloc
        self.path = urlparse(raw_url).path
        self.params = parse_qs(urlparse(raw_url).query, True)
    
    def getAbsoluteUrl(self):
        """ 
        Build the absolute url.
        Normalize everything to http
        TODO: Enable networks urls
        """
        return self.getBaseUrl() + self.path

    def getBaseUrl(self):
        """
        Return the base url
        http://domain.tdl
        """
        url = self.scheme if self.scheme != "" else "http"
        url += "://" + self.netloc
        return url

    def getFullUrl(self):
        return self.getAbsoluteUrl() + urlencode(self.params)
    
    def getPayloadedUrl(self, target_key, payload):
        """
        Build an absolute url with the given payload in
        the specified parameter
        """
        new_params = self.params.copy()
        for k, v in new_params.iteritems():
            if k == target_key:
                del new_params[k]
                new_params[k] = v[0] + payload
        encoded_params = urlencode(new_params)

        return self.getAbsoluteUrl() + "?" + encoded_params

