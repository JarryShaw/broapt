# -*- coding: utf-8 -*-

import os

import yaml

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import SafeLoader as Loader


class ConfigError(Exception):
    pass


def parse(root):
    with open(os.path.join(root, 'api.yml')) as yaml_file:
        context = yaml.load(yaml_file, Loader=Loader)

    for (env, val) in context.get('environment', dict()).items():
        os.environ[env] = str(val)

    return context
