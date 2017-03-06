# -*- coding: utf-8 -*-
import logging
import socket
import asyncio
from struct import pack, unpack

from utils import config


class Client(asyncio.Protocol):

    def connection_made(self, transport):
        self.transport = transport
        self.server_transport = None
        self.hostname = None

    def data_received(self, data):
        self.server_transport.write(data)

    def connection_lost(self, exc):
        logging.info('connected to {} success!'.format(self.hostname))
        self.server_transport.close()


class ProxyServer(asyncio.Protocol):
    INIT, HOST, DATA = 0, 1, 2

    def connection_made(self, transport):
        self.transport = transport
        self.state = self.INIT

    def connection_lost(self, exc):
        self.transport.close()

    def data_received(self, data):

        if self.state == self.INIT:
            # 解析proxyclient传过来的第一个包
            l = unpack('!i', data[:4])[0]
            _, hostname, port = unpack('!i%ssH' % l, data)

            # 与web站点建立连接
            logging.info('request connect to {}:{}'.format(hostname, port))
            asyncio.ensure_future(self.connect(hostname, port))
            self.state = self.DATA

        elif self.state == self.DATA:
            self.client_transport.write(data)

    async def connect(self, hostname, port):
        loop = asyncio.get_event_loop()
        # 连接web, only use ipv4
        transport, client = await loop.create_connection(Client,
                                                         hostname,
                                                         port,
                                                         family=socket.AF_INET)
        client.server_transport = self.transport
        self.client_transport = transport
        client.hostname = hostname

        # 返回给浏览器
        hostip, port = transport.get_extra_info('sockname')
        host = unpack("!I", socket.inet_aton(hostip))[0]
        self.transport.write(
            pack('!BBBBIH', 0x05, 0x00, 0x00, 0x01, host, port))


if __name__ == '__main__':
    # log
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')

    # config
    server = config['default']['server']
    server_port = config['default']['server_port']

    loop = asyncio.get_event_loop()
    srv = loop.create_server(ProxyServer, server, server_port)
    logging.info('start server at {}:{}'.format(server, server_port))
    loop.run_until_complete(srv)
    loop.run_forever()
