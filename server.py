# -*- coding: utf-8 -*-
import logging
import socket
import asyncio
from struct import pack, unpack

import enet
import uvloop

from utils import config


class Client(asyncio.Protocol):

    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data):
        packet = enet.Packet(data)
        self.transport.peer.send(self.transport.channelID, packet)

    def connection_lost(self, exc):
        pass


class EnetServer(object):
    INIT, HOST, DATA = 0, 1, 2

    def __init__(self, loop, host, port):
        self.loop = loop
        self.host = enet.Host(
            address=enet.Address(host.encode("utf-8"), port),
            peerCount=10,
            channelLimit=0,
            incomingBandwidth=0,
            outgoingBandwidth=0,
        )
        # 连接管理 {channel_id: [state, transport]}
        self.connections = {}

    async def run(self):

        while True:
            # enet event 阻塞函数
            event = await self.loop.run_in_executor(None, self.host.service, 0)

            # 连接时调用
            if event.type == enet.EVENT_TYPE_CONNECT:
                logging.info("proxy client [{}]: CONNECT".format(event.peer.address))

            # 断开时调用
            elif event.type == enet.EVENT_TYPE_DISCONNECT:
                logging.info("proxy client [{}]: DISCONNECT".format(event.peer.address))
                # 重置状态
                self.connections = {}

            # 接收时调用
            elif event.type == enet.EVENT_TYPE_RECEIVE:
                await self.data_received(event)

    async def data_received(self, event):
        conn_tuple = self.connections.get(event.channelID)
        if conn_tuple is None:
            self.connections[event.channelID] = [self.INIT, None]

        data = event.packet.data

        if data == b"EOF":
            # 关闭连接
            if event.channelID in self.connections:
                _, transport = self.connections.pop(event.channelID)
                if transport:
                    transport.close()

                return

        if self.connections[event.channelID][0] == self.INIT:
            # 解析proxyclient传过来的第一个包
            head = unpack('!i', data[:4])[0]
            _, hostname, port = unpack('!i%ssH' % head, data)

            # 与web站点建立连接
            logging.debug('{}: 建立TCP连接 {}:{}'.format(event.channelID, hostname, port))

            # 须避免阻塞
            asyncio.create_task(self.connect(hostname, port, event))

        elif self.connections[event.channelID][0] == self.DATA:
            logging.debug('{}: relay数据'.format(event.channelID))
            self.connections[event.channelID][1].write(data)

    async def connect(self, hostname, port, event):
        try:
            transport, client = await self.loop.create_connection(Client,
                                                             hostname,
                                                             port,
                                                             family=socket.AF_INET)
        except Exception:
            logging.error('Could not connect host: {}'.format(hostname))
            # 发送ERR
            packet = enet.Packet(b"ERR")
            event.peer.send(event.channelID, packet)

            return False

        self.connections[event.channelID][0] = self.DATA

        self.connections[event.channelID][1] = transport
        transport.peer = event.peer
        transport.channelID = event.channelID


        # 返回给浏览器
        hostip, port = transport.get_extra_info('sockname')
        host = unpack("!I", socket.inet_aton(hostip))[0]

        packet = enet.Packet(pack('!BBBBIH', 0x05, 0x00, 0x00, 0x01, host, port))
        event.peer.send(event.channelID, packet)
        logging.debug('{}: 返回响应 {}:{}'.format(event.channelID, hostname, port))


async def main():
    # log
    log_level = logging.DEBUG
    logging.basicConfig(level=log_level,
                        format='%(threadName)10s %(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')
    logging.getLogger('asyncio').setLevel(log_level)

    loop = asyncio.get_running_loop()
    # 配置
    server = config.get('default', 'server')
    server_port = config.getint('default', 'server_port')

    enet_server = EnetServer(loop, server, server_port)

    logging.info('start server at {}:{}'.format(server, server_port))
    await enet_server.run()


if __name__ == '__main__':
    with asyncio.Runner(loop_factory=uvloop.new_event_loop) as runner:
        asyncio.run(main())
