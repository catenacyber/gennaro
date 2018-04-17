#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2017 Philippe Antoine <p.antoine@catenacyber.fr>


import subprocess
import os


#TODO as an option
proxyCmd = ["python",  "gennaro/proxyfuzz.py", "-d", "127.0.0.1:8002"]
clientCmd = ["./wapiti-3.0.0/bin/wapiti", "--flush-session", "-u" "http://127.0.0.1:1526/"]
pidFileName = "WordPress/logs/httpd.pid"


#TODO? launch target as well

#TODO return code check
pidFile = open(pidFileName, "r")
pidTarget = int(pidFile.readline())
pidFile.close()
FNULL = open(os.devnull, 'w')
proxyProc = subprocess.Popen(proxyCmd)

#TODO number of times as an option
for i in range(50):
    if proxyProc.poll() != None:
        break
    clientProc = subprocess.Popen(clientCmd, stdout=FNULL)
    while clientProc.poll() == None:
        if proxyProc.poll() != None:
            clientProc.kill()
        #check PID of target
        try:
            # TODO avoid race condition with better check of target
            os.kill(pidTarget, 0)
        except OSError:
            print "Target has been fuzzed down"
            proxyProc.kill()

if proxyProc.poll() == None:
    proxyProc.kill()
