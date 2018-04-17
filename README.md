Introducing gennaro, a blind fuzzing system for server applications.
It is only a Proof of Concept.

1 Installation
=========

1.1 Prerequisites
--------------

* the target server application to be fuzzed
* radamsa : https://github.com/aoh/radamsa
* one client : for instance, for a web server, that can be a crawler or a vuln scanner (see wapiti : http://wapiti.sourceforge.net)

1.2 Configuration
-------------------

For the moment, there are missing command line options, and the code needs to be directly modified.
In catfuzz.py, we can modify :
* proxyCmd : how to launch the proxy, address and port of the target application to be fuzzed
* clientCmd : how to launch the client

In proxyfuzz.py, we can :
* change the path to radamsa binary

1.3 Launch
-------------------

After configuration, it is as simple as `python catfuzz.py`

2 Architecture
==========

The system is made of 4 elements :
* Server application to be fuzzed
* A proxy
* A client
* A script wrapper

The wrapper launches the proxy, and then keep launching the client client.
The proxy transmits every request from the client to the server and the answer back.
Then, it sends a fuzzed request.


3 TODO
======

Remove HTTP-aware fuzzing to remain protocol independent
Remove pidfile to be able to fuzz an application on another machine
