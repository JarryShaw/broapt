# -*- coding: utf-8 -*-

import copy
import dataclasses
import multiprocessing
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
    remote: bool
    report: str

    workdir: str
    environ: dict
    install: list
    scripts: list

    inited: bool = False
    locked: bool = False


class ConfigError(Exception):
    pass


class DefaultNotFoundError(ConfigError):
    pass


class ReportNotFoundError(ConfigError):
    pass


def parse_cmd(context, mimetype, environ):
    cfg_workdir = context.get('workdir', '.')
    cfg_install = context.get('install', list())
    cfg_scripts = context.get('scripts', list())

    cfg_remote = context.get('remote', False)
    cfg_report = context.get('report')
    if cfg_report is None:
        raise ReportNotFoundError

    cfg_environ = copy.deepcopy(environ)
    for key, val in context.get('environ', dict()).items():
        cfg_environ[str(key)] = str(val)

    API_DICT[mimetype] = API(
        remote=cfg_remote,
        report=cfg_report,
        workdir=cfg_workdir,
        environ=cfg_environ,
        install=cfg_install,
        scripts=cfg_scripts,
        inited=multiprocessing.Value('B', False),
        locked=multiprocessing.Value('B', False),
    )


def parse(root):
    with open(os.path.join(root, 'api.yml')) as yaml_file:
        context = yaml.load(yaml_file, Loader=Loader)

    environ = dict()
    for (env, val) in context.get('environment', dict()).items():
        environ[str(env)] = str(val)

    example = context.get('example')
    if example is None:
        raise DefaultNotFoundError
    parse_cmd(example, 'example', environ)

    for media_type in MEDIA_TYPE:
        top_level = context.get(media_type)
        if top_level is None:
            continue
        for (subtype, value) in top_level.items():
            if value is None:
                continue
            mimetype = f'{media_type}/{subtype}'.lower()
            parse_cmd(value, mimetype, environ)

    return API_DICT
