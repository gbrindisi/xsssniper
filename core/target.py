#/usr/bin/python

from urlparse import urlparse
from urlparse import parse_qs
from urllib import urlencode

class Target:
    def __init__(self, raw_url, method = 'GET', data = None):
        """
        raw_url is target url in string form
        method is POST/GET
        data is POST data
        """
        self.rawurl = raw_url
        self.scheme = urlparse(raw_url).scheme
        self.netloc = urlparse(raw_url).netloc
        self.path = urlparse(raw_url).path
        self.method = method
        if method is 'POST':
            self.params = parse_qs(data, True)
        else:
            self.params = parse_qs(urlparse(raw_url).query, True)

    def getAbsoluteUrl(self):
        """ 
        Build the absolute url.
        Normalize everything to http
        TODO: Enable networks urls
        """
        if self.method is 'POST':
            return self.rawurl
        else:
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
        Return an array [url, data]
        for GET targets payloads are hard coded in url
        for POST targets payloads are added to data
        """
        new_params = self.params.copy()
        for k, v in new_params.iteritems():
            if k == target_key:
                del new_params[k]
                new_params[k] = v[0] + payload
        encoded_params = urlencode(new_params)
        
        # Target is POST
        if self.method is 'POST':
            return [self.getAbsoluteUrl(), encoded_params]
        else:
            # Target is GET
            return [self.getAbsoluteUrl() + "?" + encoded_params, None]

