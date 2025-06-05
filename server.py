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
        # connection manager {channel_id: [state, transport]}
        self.connections = {}

    async def run(self):

        while True:
            event = await self.loop.run_in_executor(None, self.host.service, 0)

            if event.type == enet.EVENT_TYPE_CONNECT:
                logging.info("[Enet Client] [{}]: CONNECT".format(event.peer.address))

            elif event.type == enet.EVENT_TYPE_DISCONNECT:
                logging.info("[Enet Client] [{}]: DISCONNECT".format(event.peer.address))
                # reset connections
                self.connections = {}

            elif event.type == enet.EVENT_TYPE_RECEIVE:
                await self.data_received(event)

    async def data_received(self, event):
        conn_tuple = self.connections.get(event.channelID)
        if conn_tuple is None:
            self.connections[event.channelID] = [self.INIT, None]

        data = event.packet.data

        if data == b"EOF":
            # close transport
            if event.channelID in self.connections:
                _, transport = self.connections.pop(event.channelID)
                if transport:
                    transport.close()

                return

        if self.connections[event.channelID][0] == self.INIT:
            # parse request packet
            head = unpack('!i', data[:4])[0]
            _, hostname, port = unpack('!i%ssH' % head, data)

            # connect web site
            logging.info('ChannelID [{}]: Make TCP Request {}:{}'.format(event.channelID, hostname.decode("utf-8"), port))

            asyncio.create_task(self.connect(hostname, port, event))

        elif self.connections[event.channelID][0] == self.DATA:
            logging.debug('ChannelID [{}]: Relay DATA'.format(event.channelID))
            self.connections[event.channelID][1].write(data)

    async def connect(self, hostname, port, event):
        try:
            transport, client = await self.loop.create_connection(Client,
                                                             hostname,
                                                             port,
                                                             family=socket.AF_INET)
        except Exception:
            logging.error('ChannelID [{}]: Could Not Connect {}:{}'.format(event.channelID, hostname.decode("utf-8"), port))
            # Send ERR
            packet = enet.Packet(b"ERR")
            event.peer.send(event.channelID, packet)

            return False

        self.connections[event.channelID][0] = self.DATA

        self.connections[event.channelID][1] = transport
        transport.peer = event.peer
        transport.channelID = event.channelID


        # send to proxy server
        hostip, port = transport.get_extra_info('sockname')
        host = unpack("!I", socket.inet_aton(hostip))[0]

        packet = enet.Packet(pack('!BBBBIH', 0x05, 0x00, 0x00, 0x01, host, port))
        event.peer.send(event.channelID, packet)
        logging.debug('ChannelID [{}]: Relay TCP'.format(event.channelID))


async def main():
    # log
    log_level = logging.INFO
    debug = config.getboolean('default', 'debug')
    if debug:
        log_level = logging.DEBUG

    logging.basicConfig(
        level=log_level,
        format='%(threadName)10s %(asctime)s %(levelname)-8s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        filemode='a+',
    )
    logging.getLogger('asyncio').setLevel(log_level)

    # main event loop
    loop = asyncio.get_running_loop()

    # enet server
    server = config.get('default', 'server')
    server_port = config.getint('default', 'server_port')
    enet_server = EnetServer(loop, server, server_port)

    logging.info('Start [Enet Server] at {}:{}'.format(server, server_port))
    await enet_server.run()


if __name__ == '__main__':
    with asyncio.Runner(loop_factory=uvloop.new_event_loop) as runner:
        asyncio.run(main())
