# -*- coding: utf-8 -*-

import dataclasses
import os

import yaml

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import SafeLoader as Loader

# possible media types
MEDIA_TYPE = ('application',
              'audio',
              # 'example',  ## preserved for default API
              'font',
              'image',
              'message',
              'model',
              'multipart',
              'text',
              'video')

# API entries
API_DICT = dict()


# API entry
@dataclasses.dataclass
class API:
    _inited: bool
    environ: dict
    install: list
    scripts: list
    workdir: str

    install_log: int = 1
    scripts_log: int = 1


class ConfigError(Exception):
    pass


class DefaultNotFoundError(ConfigError):
    pass


class ScriptsNotFoundError(ConfigError):
    pass


def parse_cmd(context, mimetype):
    cfg_environ = context.get('environ', dict())
    cfg_install = context.get('install', list())
    cfg_workdir = context.get('workdir', '.')
    cfg_scripts = context.get('scripts')
    if cfg_scripts is None:
        raise ScriptsNotFoundError

    environ = dict()
    for (env, val) in cfg_environ.items():
        environ[str(env)] = os.path.expandvars(str(val))

    API_DICT[mimetype] = API(
        _inited=False,
        environ=environ,
        install=cfg_install,
        scripts=cfg_scripts,
        workdir=cfg_workdir,
    )


def parse(root):
    with open(os.path.join(root, 'api.yml')) as yaml_file:
        context = yaml.load(yaml_file, Loader=Loader)

    for (env, val) in context.get('environment', dict()).items():
        os.environ[str(env)] = os.path.expandvars(str(val))

    example = context.get('example')
    if example is None:
        raise DefaultNotFoundError
    parse_cmd(example, 'example')

    for media_type in MEDIA_TYPE:
        top_level = context.get(media_type)
        if top_level is None:
            continue
        for (subtype, value) in top_level.items():
            if value is None:
                continue
            mimetype = f'{media_type}/{subtype}'.lower()
            parse_cmd(value, mimetype)

    return API_DICT
