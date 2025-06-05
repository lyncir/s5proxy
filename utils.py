# -*- coding: utf8 -*-
import os
import configparser


_base_dir = os.path.abspath(os.path.dirname(__file__))


def load_config(filename):
    """
    load config file

    :param str filename: file path
    """
    config = configparser.ConfigParser()
    file_path = os.path.join(_base_dir, filename)
    config.read(file_path)
    print("Loaded config from path: {}".format(file_path))
    if 'default' not in config:
        raise IOError('Unable to load configuration file "{}"'.format(filename))

    # 必选字段
    for k in ['server', 'server_port', 'local', 'local_port', 'debug']:
        if k not in config['default']:
            raise KeyError('Not found field: "{}"'.format(k))

    return config


config = load_config('config.ini')
