# -*- coding: utf8 -*-

import ssl
import time
import select
import struct
import socket
import logging
import traceback
import SocketServer

import utils


config = utils.get_config()


def send_all(sock, data):
    bytes_sent = 0
    while True:
        r = sock.send(data[bytes_sent:])
        if r < 0:
            return r
        bytes_sent += r
        if bytes_sent == len(data):
            return bytes_sent


def send2server(sock, remote):
    try:
        fdset = [sock, remote]
        while True:
            r, w, e = select.select(fdset, [], [])
            if sock in r:
                data = sock.recv(4096)
                if len(data) <= 0:
                    break
                result = send_all(remote, data)
                if result < len(data):
                    raise Exception('failed to send all data')

            if remote in r:
                data = remote.recv(4096)
                if len(data) <= 0:
                    break
                result = send_all(sock, data)
                if result < len(data):
                    raise Exception('failed to send all data')
    finally:
        sock.close()
        remote.close()


class SSLSocketServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    
    def get_request(self):
        newsocket, fromaddr = self.socket.accept()
        connstream = ssl.wrap_socket(newsocket,
                server_side=True,
                certfile=config['certfile'],
                keyfile=config['keyfile'],
                ssl_version=ssl.PROTOCOL_TLSv1
                )
        return connstream, fromaddr


class Socks5Server(SocketServer.StreamRequestHandler):

    def handle(self):
        try:
            sock = self.connection
            #data = sock.recv(4096)
            data = self.rfile.read(4) or '\x00' * 4

            cmd = ord(data[1])
            if cmd != 1:
                logging.warn('cmd != 1')
                # send http headers
                send_all(sock, b"HTTP/1.1 200 OK\r\n")
                send_all(sock, b"Connection: close\r\n")
                send_all(sock, b"Content-Type: text/plain\r\n")
                resp = "Date: " + time.ctime() + "\r\n"
                send_all(sock, resp.encode('latin-1'))
                return

            atyp = ord(data[3])
            if  atyp == 1:
                # ipv4
                addr_ipv4 = self.rfile.read(4)
                addr = socket.inet_ntoa(addr_ipv4)
            elif atyp == 3:
                # domainname
                addr_len = self.rfile.read(1)
                addr = self.rfile.read(ord(addr_len))
            elif atyp == 4:
                # ipv6
                addr_ipv6 = self.rfile.read(16)
                addr = socket.inet_ntop(socket.AF_INET6, addr_ipv6)
            else:
                logging.warn('addr_type not support')
                # not support
                return

            addr_port = self.rfile.read(2)
            port = struct.unpack('>H', addr_port)

            try:
                remote = socket.create_connection((addr, port[0]))
                logging.info('connecting %s:%d' % (addr, port[0]))
            except socket.error, e:
                logging.warn("%s: %s" % (addr, e))
                return
            # receive request, send to server
            send2server(sock, remote)
        except socket.error, e:
            logging.warn("socket error: %s" % e)


def main():
    logging.basicConfig(level=logging.DEBUG,
            format='%(asctime)s %(levelname)-8s %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')

    LOCAL = config['server']
    PORT = config['server_port']

    server = SSLSocketServer((LOCAL, PORT), Socks5Server)
    logging.info("starting server at %s:%d" % tuple(server.server_address[:2]))
    server.serve_forever()


if __name__ == '__main__':
    main()
