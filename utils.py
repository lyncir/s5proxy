# -*- coding: utf8 -*-
import os
import configparser


_base_dir = os.path.abspath(os.path.dirname(__name__))


def load_config(filename):
    """
    加载配置文件
    """
    config = configparser.ConfigParser()
    config.read(os.path.join(_base_dir, filename))
    if 'default' not in config:
        raise IOError('Unable to load configuration file "{}"'.format(filename))

    # 必选字段
    for k in ['server', 'server_port', 'local', 'local_port']:
        if k not in config['default']:
            raise KeyError('Not found field: "{}"'.format(k))

    return config


config = load_config('config.ini')
