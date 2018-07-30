# -*- coding: utf-8 -*-
import logging
import socket
import asyncio
from struct import pack, unpack

from utils import config


class ProxyClient(asyncio.Protocol):

    def connection_made(self, transport):
        self.transport = transport
        self.server_transport = None

    def data_received(self, data):
        self.server_transport.write(data)

    def connection_lost(self, exc):
        self.server_transport.close()


class Server(asyncio.Protocol):
    INIT, HOST, DATA = 0, 1, 2

    def connection_made(self, transport):
        # 浏览器和proxyclient的transport
        self.transport = transport
        self.state = self.INIT

    def connection_lost(self, exc):
        self.transport.close()

    def eof_received(self):
        # 当接收到客户端的EOF时，转发请求到proxy server
        if self.client_transport.can_write_eof():
            self.client_transport.write_eof()

    def data_received(self, data):

        if self.state == self.INIT:
            assert data[0] == 0x05
            # server -> client. VER | METHOD
            self.transport.write(pack('!BB', 0x05, 0x00))  # no auth
            self.state = self.HOST

        elif self.state == self.HOST:
            # socks request info. VER | CMD | RSV | ATYP | SDT.ADDR | DST.PORT
            ver, cmd, rsv, atype = data[:4]
            assert ver == 0x05 and cmd == 0x01

            if atype == 3:    # domain
                length = data[4]
                hostname, nxt = data[5:5 + length], 5 + length
            elif atype == 1:  # ipv4
                hostname, nxt = socket.inet_ntop(socket.AF_INET, data[4:8]), 8
            elif atype == 4:  # ipv6
                hostname, nxt = socket.inet_ntop(socket.AF_INET6, data[4:20]), 20
            else:
                logging.warn('addr_type not suport')
                return

            port = unpack('!H', data[nxt:nxt + 2])[0]

            logging.info('request connect to {}:{}'.format(hostname, port))
            # 连接proxyserver
            asyncio.ensure_future(self.connect(hostname, port))
            self.state = self.DATA

        elif self.state == self.DATA:
            self.client_transport.write(data)

    async def connect(self, hostname, port):
        # config
        server = config.get('default', 'server')
        server_port = config.getint('default', 'server_port')

        loop = asyncio.get_event_loop()
        # 和proxyclient建立连接
        transport, client = await loop.create_connection(ProxyClient,
                                                         server,
                                                         server_port)
        # 绑定server_transport和trasport
        client.server_transport = self.transport
        self.client_transport = transport
        # 发送地址信息, 域名和端口
        self.client_transport.write(
            pack('!i%ssH' % len(hostname), len(hostname), hostname, port))


if __name__ == '__main__':
    # config
    debug = config.getboolean('default', 'debug')
    local = config.get('default', 'local')
    local_port = config.getint('default', 'local_port')

    if debug:
        debug_level = logging.DEBUG
    else:
        debug_level = logging.ERROR

    # log
    logging.basicConfig(level=debug_level,
                        format='%(threadName)10s %(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')
    logging.getLogger('asyncio').setLevel(debug_level)

    loop = asyncio.get_event_loop()
    if debug:
        loop.set_debug(enabled=True)

    srv = loop.create_server(Server, local, local_port)
    logging.info('start client at {}:{}'.format(local, local_port))
    loop.run_until_complete(srv)
    loop.run_forever()
