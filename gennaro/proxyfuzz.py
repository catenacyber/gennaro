#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2017 Philippe Antoine <p.antoine@catenacyber.fr>

import argparse
import sys
import socket
import logging
import multiprocessing
import select
import subprocess
import random

logger = logging.getLogger(__name__)
#TODO as an option
radamsa_bin = '/usr/local/bin/radamsa'


#TODO use a dictionary for fuzzing
httpMethods = ["GET", "POST", "HEAD", "TRACE", "PUT", "DELETE", "CONNECT", "OPTIONS", "PATCH"]
httpHeaders = ["Accept","Accept-Charset","Accept-Encoding","Accept-Language","Accept-Datetime","Access-Control-Request-Method","Access-Control-Request-Headers","Authorization","Cache-Control","Connection","Cookie","Content-Length","Content-MD5","Content-Type","Date","Expect","Forwarded","From","Host","If-Match","If-Modified-Since","If-None-Match","If-Range","If-Unmodified-Since","Max-Forwards","Origin","Pragma","Proxy-Authorization","Range","Referer","TE","User-Agent","Upgrade","Via", "Warning","Upgrade-Insecure-Requests","X-Requested-With","DNT","X-Forwarded-For","X-Forwarded-Host","X-Forwarded-Proto","Front-End-Https","X-Http-Method-Override","X-ATT-DeviceId","X-Wap-Profile","Proxy-Connection","X-UIDH","X-Csrf-Token","X-Request-ID","X-Correlation-ID"]

def fuzzHTTP(payload):
    methodEnd = payload.find(" ")
    if methodEnd < 0:
        return payload

    if random.randint(1, 10) < 4:
        # changes the method
        payload = httpMethods[random.randint(0, len(httpMethods)-1)] + payload[methodEnd:]
    if random.randint(1, 10) < 4:
        # adds one header
        payload = payload[:-2] + httpHeaders[random.randint(0, len(httpHeaders)-1)] + ": fuzzing\r\n\r\n"
        #TODO add relevant value
    return payload

def fuzzit(payload):
    #TODO option for HTTP aware fuzzing
    if random.randint(1, 10)  == 1:
        payload = fuzzHTTP(payload)
    fuzzCmd = [radamsa_bin, '-n', '1', '-']
    p = subprocess.Popen(fuzzCmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    mutated_data = p.communicate(payload)[0]
    return mutated_data

def startListen(port):
    #TODO option for UDP as well
    listenSocket = None
    try:
        listenSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #TODO option for address
        listenSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listenSocket.bind(('127.0.0.1', port))
        listenSocket.listen(10)
    except Exception as e:
        logger.exception('Exception while starting listening %r' % e)
        if listenSocket != None:
            listenSocket.close()
        return None
    return listenSocket

def startServer(host, port):
    #TODO option for UDP as well
    serverSocket = None
    try:
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serverSocket.connect((host, port))
    except Exception as e:
        logger.exception('Exception while starting the server %r' % e)
        if serverSocket != None:
            serverSocket.close()
        return None
    return serverSocket

class proxyProc(multiprocessing.Process):
    def __init__(self, conn, addr, destHost, destPort):
        self.conn = conn
        self.addr = addr
        self.destHost = destHost
        self.destPort = destPort
        super(proxyProc, self).__init__()
        self.daemon = True

    def receiveFull(self, conn):
        #TODO option for client timeout
        r, w, x = select.select([conn], [], [], 10)
        if not conn in r:
            raise TimeoutError
        part = conn.recv(4096)
        data = part
        #TODO option for limiting request and answer size
        while len(part) == 4096 and len(data) < 0xFFFFFF:
            part = conn.recv(4096)
            data = data + part
        if len(data) >= 0xFFFFFF:
            logger.warning('Too much data in request 0x%x bytes from %r:%r' % (len(data), self.conn, self.addr))
        return data


    def _processData(self):
        while True:
            # get a first request
            try:
                originalRequest = self.receiveFull(self.conn)
            except Exception as e:
                #TODO get sure about kind of exception
                logger.debug('Timing out connection %r from %r' % (self.conn, self.addr))
                try:
                    self.conn.shutdown(socket.SHUT_RD)
                except Exception as e:
                    logger.debug('Exception while shutting down connection %r with reason %r' % (self.conn, e))
                break

            # fuzz it and start a connection to server
            fuzzedRequest = fuzzit(originalRequest)
            self.serverSocket = startServer(self.destHost, self.destPort)
            if self.serverSocket == None:
                logger.exception('Closing connection %r at address %r' % (self.conn, self.addr))
                break
            self.serverAddr = self.serverSocket.getsockname()

            # transmit original request to server
            try:
                self.serverSocket.sendall(originalRequest)
            except Exception as e:
                self.serverSocket.close()
                logger.warning('Server closed connection reason %r for %r' % (e, self.addr))
                break

            # get original answer from server
            try:
                originalAnswer = self.receiveFull(self.serverSocket)
            except Exception as e:
                self.serverSocket.close()
                logger.debug('No answer to read %r from %r' % (self.conn, self.addr))
                break

            # transmit original answer to client
            try:
                self.conn.sendall(originalAnswer)
            except:
                self.serverSocket.close()
                logger.debug('Client closed connection before getting answer %r from %r' % (self.conn, self.addr))
                break

            # check if server is still open
            r, w, x = select.select([self.serverSocket], [], [], 0)
            if self.serverSocket in r:
                logger.debug('Server closed after original answer %r to %r' % (self.conn, self.serverAddr))
                self.serverSocket.close()
                self.serverSocket = startServer(self.destHost, self.destPort)
                if self.serverSocket == None:
                    logger.exception('Closing connection %r at address %r' % (self.conn, self.addr))
                    break
                self.serverAddr = self.serverSocket.getsockname()

            # sends fuzzed request to server
            try:
                self.serverSocket.sendall(fuzzedRequest)
            except Exception as e:
                self.serverSocket.close()
                logger.warning('Server closed connection reason %r from %r with %r mutated from %r' % (e, self.serverAddr, fuzzedRequest, originalRequest))
                break
            # tell the request is over
            self.serverSocket.shutdown(socket.SHUT_WR)

            # gets fuzzed answer from server
            try:
                fuzzedAnswer = self.receiveFull(self.serverSocket)
            except TimeoutError as e:
                self.serverSocket.close()
                logger.warning('Timeout for answer to fuzzed request %r from %r with %r mutated from %r' % (self.conn, self.serverAddr, fuzzedRequest, originalRequest))
                break
            except Exception as e:
                self.serverSocket.close()
                logger.debug('No answer to fuzzed request %r from %r with %r mutated from %r' % (self.conn, self.serverAddr, fuzzedRequest, originalRequest))
                break

            #restart server
            self.serverSocket.close()


    def run(self):
        logger.debug('Proxyfuzzing connection %r at address %r' % (self.conn, self.addr))

        try:
            self._processData()
        except Exception as e:
            logger.exception('Exception while handling connection %r with reason %r' % (self.conn, e))
        finally:
            logger.debug('Closing connection %r at address %r' % (self.conn, self.addr))
            self.serverSocket.close()
            self.conn.close()


def main():
    parser = argparse.ArgumentParser(description='proxyfuzz.py, a network proxy adding fuzzing to requests by client')

    parser.add_argument('-p', '--port', default='1526', help='port to listen to')
    parser.add_argument('-d', '--dest', default='127.0.0.1:1629', help='server to connect to')
    parser.add_argument('-l', '--log-level', default='INFO', help='DEBUG, INFO, WARNING, ERROR, CRITICAL')
    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.log_level), format='%(asctime)s - %(levelname)s - pid:%(process)d - %(message)s')

    try:
        port = int(args.port)
    except Exception as e:
        logger.exception('Invalid argument %r' % e)
        sys.exit(1)
    try:
        destParsed = args.dest.split(":")
        destHost = '127.0.0.1'
        destPort = 1629
        if len(destParsed) > 2:
            logger.exception('Invalid argument %r' % e)
            sys.exit(1)
        elif len(destParsed) > 0:
            destHost = destParsed[0]
            if len(destParsed) == 2:
                destPort = int(destParsed[1])
    except Exception as e:
        logger.exception('Invalid argument %r' % e)
        sys.exit(1)

    listenSocket = startListen(port)
    if listenSocket == None:
        sys.exit(2)
    logger.info('Starting server socket')

    try:
        while True:
            conn, addr = listenSocket.accept()
            logger.debug('Accepted connection %r from address %s' % (conn, addr))
            connProc = proxyProc(conn, addr, destHost, destPort)
            connProc.start()
    except Exception as e:
        logger.exception('Exception while running the server %r' % e)
    finally:
        logger.info('Closing server socket')
        listenSocket.close()
        sys.exit(0)

if __name__ == '__main__':
    main()
