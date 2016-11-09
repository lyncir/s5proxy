# -*- coding: utf8 -*-

import ssl
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


class ThreadingTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    allow_reuse_address = True


class Socks5Client(SocketServer.StreamRequestHandler):

    def handle(self):
        try:
            sock = self.connection
            # client -> server. VER | NMETHODS | METHODS
            sock.recv(262)
            # server -> client. VER | METHOD
            sock.send("\x05\x00")
            # socks request info. VER | CMD | RSV | ATYP | SDT.ADDR | DST.PORT
            data = self.rfile.read(4) or '\x00' * 4
            cmd = ord(data[1])
            if cmd != 1:
                logging.warn('cmd != 1')
                return

            atyp = ord(data[3])
            req = data
            if  atyp == 1:
                # ipv4
                addr_ipv4 = self.rfile.read(4)
                addr = socket.inet_ntoa(addr_ipv4)
                req += addr_ipv4
            elif atyp == 3:
                # domainname
                addr_len = self.rfile.read(1)
                addr = self.rfile.read(ord(addr_len))
                req += addr_len + addr
            elif atyp == 4:
                # ipv6
                addr_ipv6 = self.rfile.read(16)
                addr = socket.inet_ntop(socket.AF_INET6, addr_ipv6)
                req += addr_ipv6
            else:
                logging.warn('addr_type not support')
                # not support
                return
            addr_port = self.rfile.read(2)
            req += addr_port
            port = struct.unpack('>H', addr_port)
            try:
                # socks response info. VER | REP | RSV | ATYP | BND.ADDR | BND.PORT 
                reply = "\x05\x00\x00\x01"
                reply += socket.inet_aton('0.0.0.0') + struct.pack('>H', 2222)
                self.wfile.write(reply)
                # send request to proxy server. TODO: encrypt
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLSv1)
                remote.connect((config['server'], config['server_port']))
                remote.send(req)
                logging.info('connecting %s:%d' % (addr, port[0]))
            except socket.error, e:
                logging.warn("connected server %s:%d error. %s" % (config['server'],
                    config['server_port'], e))
                return
            # send and receive. TODO: encrypt
            send2server(sock, remote)
        except socket.error, e:
            logging.warn("socket error: %s" % e)


def main():
    logging.basicConfig(level=logging.DEBUG,
            format='%(asctime)s %(levelname)-8s %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')

    LOCAL = config['local']
    PORT = config['local_port']

    server = ThreadingTCPServer((LOCAL, PORT), Socks5Client)
    logging.info("starting client at %s:%d" % tuple(server.server_address[:2]))
    server.serve_forever()


if __name__ == '__main__':
    main()
