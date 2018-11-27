#!/usr/bin/python
# -*- coding: utf-8 -*-
# This is a python 2/3 hybrid file
"""
The script allows arbitrary socket and HTTP(S) connections via:
- socket and ssl-wrapped sockets - when you need bare bone or non-HTTP(S)
- python urllib/urllib2 HTTP(S) library - when you need HTTP(S) and a little bit more automated HTTP feature handling
- python requests HTTP(S) library - when you need HTTP(S) and full HTTP feature handling
- python treq (uses Python Twisted and therefore asynchronous IO) - when you need full HTTP(S) feature handling and speed is important

The main features are:
- Works under python 2.7 and python 3 (although treq here is untested under python 2.7)
- You can just copy and paste an HTTP(S) request (e.g. from a proxy software) without worrying about the parsing and other details
- You can also use the sockets functions to do non-HTTP related things
- Ignores any certificate warnings for the server

It should be helpful when:
- You want to script HTTP(S) requests (e.g. just copy-paste from a proxy like Burp), for example during a pentest or CTF
- When you encounter a CTF challenge running on a server (like "nc example.org 1234") or a proprietary TCP protocol during pentests

Howto:
- Change the variables START, END and TLS
- Optional: Change further configuration options, such as sending the HTTP(S) requests through a proxy
- Change the 'main' function to send the request you would like to. By default it will send 3 HTTP requests to www.example.org with every library.

----------------------------------------------------------------------------
"THE BEER-WARE LICENSE" (Revision 42):
<floyd at floyd dot ch> wrote this file. As long as you retain this notice you
can do whatever you want with this stuff. If we meet some day, and you think
this stuff is worth it, you can buy me a beer/coffee in return
floyd http://floyd.ch @floyd_ch <floyd at floyd dot ch>
November 2018
----------------------------------------------------------------------------
Created on 2018 November 26
@author: floyd, http://floyd.ch, @floyd_ch
"""

###############################
###
# imports
###
###############################

from __future__ import print_function
from builtins import bytes
import socket
import ssl
import time
import sys

REQUESTS_LIB = False
try:
    import requests
    # we don't want to see warnings about insecure certificates
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    REQUESTS_LIB = True
except:
    print("Warning: You do not have the 'requests' library installed in python. This script will only work partially (with urllib). Run 'pip install requests' for your python version.")
    
TREQ_LIB = False
try:
    import treq
    from twisted.internet import reactor
    import twisted.internet._sslverify as sslverify
    sslverify.platformTrust = lambda : None
    from twisted.web.error import Error as TwistedWebError
    from twisted.internet.error import ConnectionRefusedError
    from twisted.internet.error import TimeoutError
    from OpenSSL.SSL import Error as OpenSSLError
    TREQ_LIB = True
except:
    print("Warning: You do not have the 'treq' library installed in python. This script will only work partially. Run 'pip install treq' for your python version.")

if not REQUESTS_LIB or not TREQ_LIB:
    time.sleep(1)

if sys.version_info >= (3, 0):
    # python 3
    if sys.getdefaultencoding().lower() != 'utf-8' or sys.stdout.encoding.lower() != 'utf-8':
        # Solving this issue can be arbitrarily complex, see:
        # https://stackoverflow.com/questions/2276200/changing-default-encoding-of-python#17628350
        # http://www.ianbicking.org/illusive-setdefaultencoding.html
        # etc.
        # TL;DR: UnicodeEncodeError: 'ascii' codec can't encode character '\xe4' in position 33: ordinal not in range(128)
        # For now, just tell the user and refuse to run without UTF-8:
        print("Sorry, your default encoding seems to be something else than UTF-8")
        print("This means any umlauts in the text will explode in your face when you try to print them.")
        print("sys.getdefaultencoding(): "+sys.getdefaultencoding())
        print("sys.stdout.encoding: "+sys.stdout.encoding)
        print("Please set environment correctly, for example something like:")
        print("export LC_CTYPE=utf-8")
        print("export PYTHONIOENCODING=utf-8")
        exit()
    import urllib.request, urllib.error, urllib.parse
else:
    # python 2
    import urllib2
    

###############################
###
# MANDATORY: YOUR HTTP REQUEST
###
###############################

# Just paste an HTTP request into START and END
# START is everything before the part where you want to inject...
START = """GET / HTTP/1.1
Host: www.example.org
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:63.0) Gecko/20100101 Firefox/63."""

# ... END is everything after the part where you want to inject
END = """
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: de,en-US;q=0.7,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1

"""

# if SSL/TLS should be used
TLS = False

###############################
###
# OPTIONAL:
###
###############################
DEBUG = False  # More debug output
TIMEOUT = 2   # Timeout for sockets and HTTP connections
MAX_DATA_RECV_SOCKET = 10 * 1024  #Maximum amount of data we accept back from the socket
RECV_BUFF = 1280  #recv() call size

# proxy functionality available with the requests and treq library
# Not with urllib or sockets
# sending the request through a proxy (e.g. Burp) - 127.0.0.1:8080
SEND_THROUGH_PROXY = False

###############################
###
# MANDATORY: What you want the program to do
###
###############################

def main():
    # EXAMPLE: Send numbers 0 and 1 as Firefox User-Agent minor version:
    corpus = range(0, 2)
    if TREQ_LIB:
        treq_sender = TreqSender()
    for i in corpus:
        info("Trying", i)
        # parsing the raw request
        req = RawHttpRequest(START + str(i) + END, TLS)
        
        if REQUESTS_LIB:
            info("sending it with the requests library (which is the most sane choice and can return what we expect - the body HTML)")
            result(repr(send_requests(req)[:60])+ "...") 
            #result(repr(send_requests(req)))
            #r = send_requests(req, entire_response=True)
            #info(r.request.headers)
        
        info("Sending it with the urllib library, wouldn't process Content-Encoding (HTML would be gzip'ed) if we wouldn't remove Accept-Encoding in request")
        result(repr(send_urllib(req)[:60]) + "...")
        #result(repr(send_urllib(req)))
        #resp = send_urllib(req, entire_response=True)
        #info(resp.info())
        
        info("Sending it via socket, which doesn't know the HTTP protocols and also returns the HTTP headers and also a gziped body (method doesn't remove Accept-Encoding)")
        #req = RawRequest(START + str(i) + END, TLS, HOST, PORT)
        result(repr(send_socket(req)[:60]) + "...")
        #result(repr(send_socket(req)))
        
        # If we need to do it quickly we can send it via Python Twisted and Treq is a higher level API for it
        # The API is kept very similar to requests
        # However, as asynchronous network io works very differently from a code perspective, this will need a callback function
        if TREQ_LIB:
            treq_sender.add(req)
        
        # When debugging, wait 15 seconds after every request that is sent
        if DEBUG:
            time.sleep(15)
        print()
        
    if TREQ_LIB:
        # When everything is passed to Twisted, start the work
        info("Sending via treq/Twisted all at once with asynchronous io")
        treq_sender.run()

###############################
###
# END: Usually you hopefully don't need to change things below here
###
###############################


###############################
###
# treq methods
###
###############################

class TreqSender(object):
    
    def __init__(self):
        self.added = 0
        self.done = 0
    
    def add(self, req):
        self.send_treq(req, self.response_callback)
        self.added += 1
    
    def stop_reactor(self):
        try:
            reactor.stop()
        except Exception as e:
            error(e)

    def body_callback(self, body):
        # HERE! This is what you want to implement for treq
        result(repr(body[:60]) + "...")
        
        self.done += 1
        if self.done >= self.added:
            self.stop_reactor()

    # For the treq callback
    def response_callback(self, response):
        r = response.content()
        r.addCallback(self.body_callback)
    
    def run(self):
        reactor.run()

    def send_treq(self, req, callback, allow_redirects=True):
        # Note how similar this is to the requests library...
        proxy_dict = None
        if SEND_THROUGH_PROXY:
            http_proxy  = "http://127.0.0.1:8080"
            https_proxy = "https://127.0.0.1:8080"

            proxy_dict = { 
                          "http"  : http_proxy, 
                          "https" : https_proxy, 
                        }
        headers = dict(req.header_tuples)
        r = treq.request(req.method, req.url, data=req.body, headers=headers, proxies=proxy_dict, verify=False, timeout=TIMEOUT, allow_redirects=allow_redirects)
        r.addCallback(callback)

###############################
###
# requests library methods, see http://docs.python-requests.org/en/master/api/
###
###############################


def send_requests(req, entire_response=False, allow_redirects=True):    
    proxy_dict = None
    if SEND_THROUGH_PROXY:
        http_proxy  = "http://127.0.0.1:8080"
        https_proxy = "https://127.0.0.1:8080"

        proxy_dict = { 
                      "http"  : http_proxy, 
                      "https" : https_proxy, 
                    }
    headers = dict(req.header_tuples)
    r = requests.request(req.method, req.url, data=req.body, headers=headers, proxies=proxy_dict, verify=False, timeout=TIMEOUT, allow_redirects=allow_redirects)
    if entire_response:
        return r
    else:
        return r.text

###############################
###
# urllib methods
###
###############################

def send_urllib(req, entire_response=False):
    if sys.version_info >= (3, 0):
        return send_urllib_python3(req, entire_response=entire_response)
    else:
        return send_urllib_python2(req, entire_response=entire_response)

def send_urllib_python3(req, entire_response=False):    
    opener = urllib.request.build_opener()
    opener.addheaders = req.header_tuples
    urllib.request.install_opener(opener)
    try:
        start = time.time()
        if not req.method in ("GET", "POST"):
            Exception("urllib does not support anything than GET/POST very well") 
        response = urllib.request.urlopen(req.url, req.body, TIMEOUT)
        time_taken = time.time() - start
        response.time_taken = time_taken
        if entire_response:
            return response
        else:
            return response.read()
    except urllib.error.HTTPError as e:
        error('The server couldn\'t fulfill the request. Error code:', e.code)
    except urllib.error.URLError as e:
        error("URLError:", e.reason)
    except Exception as e:
        error("DIDNT WORK:", e)

def send_urllib_python2(req, entire_response=False):    
    opener = urllib2.build_opener()
    opener.addheaders = req.header_tuples
    urllib2.install_opener(opener)
    try:
        start = time.time()
        if not req.method in ("GET", "POST"):
            Exception("urllib2 does not support anything than GET/POST very well") 
        response = urllib2.urlopen(req.url, req.body, TIMEOUT)
        time_taken = time.time() - start
        response.time_taken = time_taken
        if entire_response:
            return response
        else:
            return response.read()
    except urllib2.HTTPError as e:
        error('The server couldn\'t fulfill the request. Error code:', e.code)
    except urllib2.URLError as e:
        error("URLError:", e.reason)
    except Exception as e:
        error("DIDNT WORK:", e)


###############################
###
# socket methods
###
###############################

def send_socket(req):
    # sys.stdout.write('.')
    # sys.stdout.flush()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((req.host, req.port))
    if req.tls:
        # ignores any certificate checks etc. by default
        s = ssl.wrap_socket(s)
    s.settimeout(TIMEOUT)
    
    raw = req.raw
    try:
        s.sendall(raw.encode("utf-8"))
    except Exception as e:
        error("Socket closed on server side or something else went wrong with socket while sending: ", e)
    buf = b""
    data = b""
    while 1:
        try:
            data = s.recv(RECV_BUFF)
        except socket.timeout as to:
            # connection timed out
            pass
        except Exception as e:
            print("Error occured while reading")
            error(e)
            break
        if not data:
            break
        buf += data
        #print "Received:", repr(data)
        if len(buf) >= MAX_DATA_RECV_SOCKET:
            break
    try:
        s.close()
    except:
        pass
    return buf

###############################
###
# generic raw request parsers
###
###############################

class RawRequest(object):
    def __init__(self, raw, tls, host=None, port=None, newline="\n"):
        self.raw = raw
        self.tls = tls
        self.host = host
        self.port = port
        self.newline = newline
        

class RawHttpRequest(RawRequest):
    REMOVE_HEADERS=[
        'content-length', 
        'accept-encoding', # helps so that gzip data is not returned
        # 'accept-charset', 
        # 'accept-language', 
        # 'accept', 
        'keep-alive', 
        'connection', 
        # 'pragma', 
        # 'cache-control'
    ]
    
    def __init__(self, raw, tls, host=None, port=None, remove_headers=None, newline="\n"):
        super(RawHttpRequest, self).__init__(raw, tls, host, port, newline)
        self.method = "GET"
        self.url = "/"
        self.header_tuples = ""
        self.body = ""
        
        self.parse(remove_headers)
        debug(str(self))
    
    def __str__(self):
        r = """Host: {}
Port: {}
TLS: {}
Newline: {}
Method: {}
URL: {}
Headers: {}
Body: {}

Raw:
{}
""".format(self.host, self.port, self.tls, repr(self.newline), self.method, self.url, dict(self.header_tuples), repr(self.body), self.raw)
        return r
    
    def parse(self, remove_headers):
        if remove_headers is None:
            remove_headers = RawHttpRequest.REMOVE_HEADERS
        remove_headers = [x.lower() for x in remove_headers]
        
        double_newline = self.newline * 2
        if double_newline in self.raw:
            headers, self.body = self.raw.split(double_newline, 1)
            if not self.body:
                self.body = None
        else:
            debug("Warning: Your request has no body")
            headers = self.raw
            self.body = None
        headers = headers.split(self.newline)
        request_line = headers[0]
        headers = headers[1:]
        
        method, rest = request_line.split(" ", 1)
        self.method = method.upper()
        url, self.protocol = rest.rsplit(" ", 1)
    
        if not url.startswith("/"):
            raise Exception("URL must start with /")
        
        if self.tls is None:
            debug("Warning: Defaulting to Non-TLS HTTP requests")
            self.tls = False
        
        extract_from_host_header = not self.host and not self.port
        
        header_tuples = []
        for header in headers:
            name, value = header.split(": ", 1)
            if extract_from_host_header and name.lower() == 'host':
                if ":" in value:
                    host, port = value.split(":", 1)
                    self.host = host
                    self.port = int(port)
                else:
                    self.host = value
                    if self.tls:
                        self.port = 443
                    else:
                        self.port = 80
                                
            if not name.lower() in remove_headers:
                header_tuples.append((name, value))
                #debug("Added header:", name)
        self.header_tuples = header_tuples
        self.create_url(url)
    
    def create_url(self, path):
        prot = "https://" if self.tls else "http://"
        if self.port == 443 and self.tls:
            self.url = prot + self.host + path
        elif self.port == 80 and not self.tls: 
            self.url = prot + self.host + path
        else:
            self.url = prot + self.host + ":" + str(self.port) + path

###############################
###
# Helpers
###
###############################

def warning(*text):
    print("[Warning] "+str(" ".join(str(i) for i in text)))

def error(*text):
    print("[ERROR] "+str(" ".join(str(i) for i in text)))

def fatalError(*text):
    print("[FATAL ERROR] "+str(" ".join(str(i) for i in text)))
    exit()

def result(*text):
    print("[RESULT] "+str(" ".join(str(i) for i in text)))

def info(*text):
    print("[INFO] "+str(" ".join(str(i) for i in text)))

def debug(*text):
    if DEBUG:
        print("[DEBUG] "+str(" ".join(str(i) for i in text)))


if __name__ == "__main__":
    main()