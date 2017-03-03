# -*- coding: utf8 -*-
import yaml


class Config(object):

    def from_ymlfile(self, filename):
        try:
            with open(filename) as config_file:
                config = yaml.load(config_file.read())
        except IOError as e:
            e.strerror = 'Unable to load configuration file (%s)' % e.strerror
            raise
        return config


config = Config().from_ymlfile('config.yml')


if __name__ == '__main__':
    print(config)
    print(config['default']['local'])
