# -*- coding: utf-8 -*-
import logging
import socket
import asyncio
from struct import pack, unpack

import enet

from utils import config


channel_transport = {}


class EnetClient(object):

    def __init__(self, loop, host, port):
        self.channel_count = 255  # NOTE: Max 256, 255 is broadcast?
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
        self.channel_ids = list(range(self.channel_count))

        self.peer = self.connect()

    async def run(self):

        while True:
            event = await self.loop.run_in_executor(None, self.enet_host.service, 0)

            event_type = event.type
            if not event or event_type == enet.EVENT_TYPE_NONE:
                # await asyncio.sleep(1)
                continue

            if event.type == enet.EVENT_TYPE_CONNECT:
                logging.info("[Enet Server] [{}]: CONNECT".format(event.peer.address))

            elif event.type == enet.EVENT_TYPE_DISCONNECT:
                logging.info("[Enet Server] [{}]: DISCONNECT".format(event.peer.address))

            elif event.type == enet.EVENT_TYPE_RECEIVE:
                data = event.packet.data

                # Process ERR
                if data == b"ERR":
                    if event.channelID in channel_transport:
                        channel_transport[event.channelID].close()
                    logging.error("ChannelID [{}]: Proxy Failed!".format(event.channelID))
                    continue

                logging.debug("ChannelID [{}]: Receive DATA".format(event.channelID))
                if event.channelID in channel_transport:
                    channel_transport[event.channelID].write(data)

    def send(self, channel_id, packet):
        # TODO: reconnect?
        if not self.peer.state:
            self.peer = self.connect()

        self.peer.send(channel_id, packet)

    def connect(self):
        logging.info("Connect to [Enet Server] {}:{}".format(self.host, self.port))
        peer = self.enet_host.connect(
            address=enet.Address(self.host.encode("utf-8"), self.port),
            channelCount=self.channel_count,
        )

        return peer


class ProxyServer(asyncio.Protocol):
    INIT, HOST, DATA = 0, 1, 2

    def __init__(self, enet_client):
        self.enet_client = enet_client
        # connection manager {port: channel_id}
        self.connections = {}

    def connection_made(self, transport):
        # transport of browser -> proxy server
        self.transport = transport
        self.state = self.INIT

        # bind channel_id
        _, self.peer_port = transport.get_extra_info('peername')
        channel_id = self.enet_client.channel_ids.pop()
        self.connections[self.peer_port] = channel_id

        channel_transport[channel_id] = transport

        logging.debug("Browser Port:[{}] Connected [Proxy Server] ChannelID:[{}]".format(self.peer_port, channel_id))


    def connection_lost(self, exc):
        # unbind channel_id
        if self.peer_port in self.connections:
            # 发送eof
            packet = enet.Packet(b"EOF")
            self.enet_client.send(self.connections[self.peer_port], packet)

            channel_id = self.connections.pop(self.peer_port)
            self.enet_client.channel_ids.append(channel_id)
            channel_transport.pop(channel_id)

        self.transport.close()

    def eof_received(self):
        # unbind channel_id
        if self.peer_port in self.connections:
            # Send EOF
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

            logging.debug("ChannelID [{}]: Socks5 ACK".format(self.connections[self.peer_port]))

        elif self.state == self.HOST:
            # socks request info. VER | CMD | RSV | ATYP | SDT.ADDR | DST.PORT
            ver, cmd, rsv, atype = data[:4]
            assert ver == 0x05 and cmd == 0x01

            if atype == 3:    # domain
                length = data[4]
                hostname, nxt = data[5:5 + length], 5 + length
            elif atype == 1:  # ipv4
                hostname, nxt = socket.inet_ntop(socket.AF_INET, data[4:8]), 8
                hostname = hostname.encode("utf-8")
            elif atype == 4:  # ipv6
                hostname, nxt = socket.inet_ntop(socket.AF_INET6, data[4:20]), 20
                hostname = hostname.encode("utf-8")
            else:
                logging.warn('addr_type not suport')
                return

            port = unpack('!H', data[nxt:nxt + 2])[0]

            logging.info('ChannelID [{}]: Send TCP Request {}:{}'.format(self.connections[self.peer_port], hostname.decode("utf-8"), port))

            # Send to Enet Server
            msg = pack('!i%ssH' % len(hostname), len(hostname), hostname, port)
            packet = enet.Packet(msg)
            self.enet_client.send(self.connections[self.peer_port], packet)

            self.state = self.DATA

        elif self.state == self.DATA:
            packet = enet.Packet(data)
            self.enet_client.send(self.connections[self.peer_port], packet)

            logging.debug('ChannelID [{}]: Send Data Request'.format(self.connections[self.peer_port]))


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

    # enet client
    server = config.get('default', 'server')
    server_port = config.getint('default', 'server_port')
    enet_client = EnetClient(loop, server, server_port)
    asyncio.create_task(enet_client.run())

    # proxy server
    local = config.get('default', 'local')
    local_port = config.getint('default', 'local_port')
    proxy_server = await loop.create_server(lambda: ProxyServer(enet_client), local, local_port)
    async with proxy_server:
        logging.info('Start [Proxy Server] at {}:{}'.format(local, local_port))
        await proxy_server.serve_forever()


if __name__ == '__main__':
    asyncio.run(main())
