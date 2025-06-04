# -*- coding: utf-8 -*-
import time
import logging
import socket
import asyncio
from struct import pack, unpack

import enet
import uvloop

from utils import config


channel_transport = {}


class EnetClient(object):

    def __init__(self, loop, host, port):
        logging.debug("Connect to {}:{}".format(host, port))
        self.loop = loop
        self.host = host
        self.port = port
        self.enet_host = enet.Host(
            address=None,
            peerCount=1,
            channelLimit=0,
            incomingBandwidth=0,
            outgoingBandwidth=0,
        )
        self.channel_ids = list(range(100))

        self.peer = self.connect()

    async def run(self):

        while True:
            # enet event 阻塞函数
            event = await self.loop.run_in_executor(None, self.enet_host.service, 0)

            event_type = event.type
            if not event or event_type == enet.EVENT_TYPE_NONE:
                # await asyncio.sleep(1)
                continue

            # 连接时调用
            if event.type == enet.EVENT_TYPE_CONNECT:
                logging.info("proxy server [{}]: CONNECT".format(event.peer.address))

            # 断开时调用
            elif event.type == enet.EVENT_TYPE_DISCONNECT:
                logging.info("proxy server [{}]: DISCONNECT".format(event.peer.address))

            # 接收时调用
            elif event.type == enet.EVENT_TYPE_RECEIVE:
                data = event.packet.data

                # 收到ERR
                if data == b"ERR":
                    channel_transport[event.channelID].close()
                    continue

                channel_transport[event.channelID].write(data)
                logging.debug("{}: 返回状态".format(event.channelID))

    def send(self, channel_id, packet):
        # TODO: 重连?
        if not self.peer.state:
            self.peer = self.connect()

        self.peer.send(channel_id, packet)

    def connect(self):
        peer = self.enet_host.connect(
            address=enet.Address(self.host.encode("utf-8"), self.port),
            channelCount=100,
        )

        return peer


class Server(asyncio.Protocol):
    INIT, HOST, DATA = 0, 1, 2

    def __init__(self, enet_client):
        self.enet_client = enet_client
        # 连接管理 {port: channel_id}
        self.connections = {}

    def connection_made(self, transport):
        # 浏览器和proxyclient的transport
        self.transport = transport
        self.state = self.INIT

        # 绑定channel_id
        _, self.peer_port = transport.get_extra_info('peername')
        channel_id = self.enet_client.channel_ids.pop()
        self.connections[self.peer_port] = channel_id

        channel_transport[channel_id] = transport

        logging.debug("{}: 浏览器与代理服务器建立连接 {}".format(self.peer_port, channel_id))


    def connection_lost(self, exc):
        # 解除绑定channel_id
        if self.peer_port in self.connections:
            # 发送eof
            packet = enet.Packet(b"EOF")
            self.enet_client.send(self.connections[self.peer_port], packet)

            channel_id = self.connections.pop(self.peer_port)
            self.enet_client.channel_ids.append(channel_id)
            channel_transport.pop(channel_id)

        self.transport.close()

    def eof_received(self):
        # 解除绑定channel_id
        if self.peer_port in self.connections:
            # 发送eof
            packet = enet.Packet(b"EOF")
            self.enet_client.send(self.connections[self.peer_port], packet)

            channel_id = self.connections.pop(self.peer_port)
            self.enet_client.channel_ids.append(channel_id)
            channel_transport.pop(channel_id)

    def data_received(self, data):

        if self.state == self.INIT:
            assert data[0] == 0x05
            # server -> client. VER | METHOD
            self.transport.write(pack('!BB', 0x05, 0x00))  # no auth
            self.state = self.HOST

            logging.debug("{}: 通过协商".format(self.connections[self.peer_port]))

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

            logging.debug('{}: 发送请求 {}:{}'.format(self.connections[self.peer_port], hostname, port))

            # 发送给proxy server, 地址信息, 域名和端口
            try:
                hostname = hostname.encode('utf-8')
            except AttributeError:
                pass

            data = pack('!i%ssH' % len(hostname), len(hostname), hostname, port)
            packet = enet.Packet(data)
            self.enet_client.send(self.connections[self.peer_port], packet)

            self.state = self.DATA

        elif self.state == self.DATA:
            packet = enet.Packet(data)
            self.enet_client.send(self.connections[self.peer_port], packet)

            logging.debug('{}: 发送数据'.format(self.connections[self.peer_port]))


async def main():
    # log
    log_level = logging.DEBUG
    logging.basicConfig(level=log_level, format='%(threadName)10s %(asctime)s %(levelname)-8s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')
    logging.getLogger('asyncio').setLevel(log_level)

    # 事件循环
    loop = asyncio.get_running_loop()

    # enet 客户端
    server = config.get('default', 'server')
    server_port = config.getint('default', 'server_port')
    enet_client = EnetClient(loop, server, server_port)
    asyncio.create_task(enet_client.run())

    # s5 前端
    local = config.get('default', 'local')
    local_port = config.getint('default', 'local_port')
    proxy_frontend = await loop.create_server(lambda: Server(enet_client), local, local_port)
    async with proxy_frontend:
        logging.info('start client at {}:{}'.format(local, local_port))
        await proxy_frontend.serve_forever()


if __name__ == '__main__':
    with asyncio.Runner(loop_factory=uvloop.new_event_loop) as runner:
        asyncio.run(main())
