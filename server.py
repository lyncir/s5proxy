# -*- coding: utf-8 -*-
import logging
import socket
import asyncio
from struct import pack, unpack
from utils import config
from http.server import BaseHTTPRequestHandler
from http.client import responses
from io import BytesIO
from datetime import datetime


class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = BytesIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message

    def send_response(self, code, message=None):
        self.send_response_only(code, message)


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

    def eof_received(self):
        # 当接收到proxy client的EOF时，转发请求给website，将会关闭整个链接
        if hasattr(self, 'client_transport') and self.client_transport.can_write_eof():
            self.client_transport.write_eof()

    def data_received(self, data):

        if self.state == self.INIT:
            # 解析proxyclient传过来的第一个包
            try:
                head = unpack('!i', data[:4])[0]
                _, hostname, port = unpack('!i%ssH' % head, data)

                # 与web站点建立连接
                logging.info('request connect to {}:{}'.format(hostname, port))
                asyncio.ensure_future(self.connect(hostname, port))
                self.state = self.DATA
            except Exception:
                # 是否是http包
                request = HTTPRequest(data)
                if not request.error_code:
                    response = {"code": 200,
                                "headers": {'Content-Type': 'text/html; charset=utf-8',
                                            'Server': 'nginx/1.10.2'},
                                "version": 'HTTP/1.1',
                                "body": "hello world"}

                    status = '{} {} {}\r\n'.format(response['version'],
                                                   response['code'],
                                                   responses[response['code']])
                    self._write_transport(status)

                    if 'body' in response and 'Content-Length' not in response['headers']:
                        response['headers']['Content-Length'] = len(response['body'])
                    response['headers']['Date'] = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S +0000")

                    for (header, content) in response['headers'].items():
                        self._write_transport('{}: {}\r\n'.format(header, content))

                    self._write_transport('\r\n')
                    if 'body' in response:
                        self._write_transport(response['body'])

                    host, port = self.transport.get_extra_info('peername')
                    if 'User-Agent' in request.headers:
                        logging.info('http response to {}:{} by {}'.format(host, port, request.headers['User-Agent']))
                    else:
                        logging.info('http response to {}:{}'.format(host, port))

        elif self.state == self.DATA:
            self.client_transport.write(data)

    def _write_transport(self, string):
        if isinstance(string, str):
            self.transport.write(string.encode('utf-8'))
        else:
            self.transport.write(string)

    async def connect(self, hostname, port):
        loop = asyncio.get_event_loop()
        # 连接web, only use ipv4
        try:
            transport, client = await loop.create_connection(Client,
                                                             hostname,
                                                             port,
                                                             family=socket.AF_INET)
        # 连接失败
        except Exception:
            logging.error('Could not connect host: {}'.format(hostname))
            if self.transport.can_write_eof():
                self.transport.write_eof()
            return False

        client.server_transport = self.transport
        self.client_transport = transport
        client.hostname = hostname

        # 返回给浏览器
        hostip, port = transport.get_extra_info('sockname')
        host = unpack("!I", socket.inet_aton(hostip))[0]
        self.transport.write(
            pack('!BBBBIH', 0x05, 0x00, 0x00, 0x01, host, port))


if __name__ == '__main__':
    # config
    debug = config.getboolean('default', 'debug')
    server = config.get('default', 'server')
    server_port = config.getint('default', 'server_port')

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
    loop.set_debug(enabled=True)

    srv = loop.create_server(ProxyServer, server, server_port)
    logging.info('start server at {}:{}'.format(server, server_port))
    loop.run_until_complete(srv)
    loop.run_forever()
