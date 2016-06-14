# -*- coding: utf8 -*-

import ConfigParser


def get_config():
    config = ConfigParser.RawConfigParser()
    config.read('config.cfg')

    cfg = {}
    cfg['server'] = config.get('default', 'server')
    cfg['server_port'] = config.getint('default', 'server_port')
    cfg['local'] = config.get('default', 'local')
    cfg['local_port'] = config.getint('default', 'local_port')
    cfg['certfile'] = config.get('default', 'certfile')
    cfg['keyfile'] = config.get('default', 'keyfile')

    return cfg


if __name__ == '__main__':
    print get_config()
