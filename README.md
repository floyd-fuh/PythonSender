# PythonSender

The script allows arbitrary socket and HTTP(S) connections via:

* socket and ssl-wrapped sockets - when you need bare bone or non-HTTP(S)
* python urllib/urllib2 HTTP(S) library - when you need HTTP(S) and a little bit more automated HTTP feature handling
* python requests HTTP(S) library - when you need HTTP(S) and full HTTP feature handling
* python treq (uses Python Twisted and therefore asynchronous IO) - when you need full HTTP(S) feature handling and speed is important


The main features are:

* Works under python 2.7 and python 3 (although treq here is untested under python 2.7)
* You can just copy and paste an HTTP(S) request (e.g. from a proxy software) without worrying about the parsing and other details
* You can also use the sockets functions to do non-HTTP related things
* Ignores any certificate warnings for the server


It should be helpful when:

* You want to script HTTP(S) requests (e.g. just copy-paste from a proxy like Burp), for example during a pentest or CTF
* When you encounter a CTF challenge running on a server (like "nc example.org 1234") or a proprietary TCP protocol during pentests


Howto:

* Change the variables START, END and TLS
* Optional: Change further configuration options, such as sending the HTTP(S) requests through a proxy
* Change the 'main' function to send the request you would like to. By default it will send 3 HTTP requests to www.example.org with every library.


See also http://www.floyd.ch/?p=1105

