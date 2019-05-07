# -*- coding: utf-8 -*-

import dataclasses
import multiprocessing
import os
import pathlib
import subprocess
import sys
import time

import yaml

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader

# repo root path
ROOT = str(pathlib.Path(__file__).parents[1].resolve())

# limit on CPU
try:
    CPU_CNT = int(os.getenv('APP_CPU'))
except (ValueError, TypeError):
    if os.name == 'posix' and 'SC_NPROCESSORS_CONF' in os.sysconf_names:
        CPU_CNT = os.sysconf('SC_NPROCESSORS_CONF')
    elif 'sched_getaffinity' in os.__all__:
        CPU_CNT = len(os.sched_getaffinity(0))  # pylint: disable=E1101
    else:
        CPU_CNT = os.cpu_count() or 1

# sleep interval
try:
    INTERVAL = int(os.getenv('APP_INT'))
except (TypeError, ValueError):
    INTERVAL = 10

# fetch environ
API_ROOT = os.getenv('API_ROOT', '/api/')
with open(os.path.join(API_ROOT, 'api.yml')) as yaml_file:
    API_CFG = yaml.load(yaml_file, Loader=Loader)
for (env, val) in API_CFG.get('environment', dict()).items():
    os.environ[env] = str(val)

# Bro config
BOOLEAN_STATES = {'1': True, '0': False,
                  'yes': True, 'no': False,
                  'true': True, 'false': False,
                  'on': True, 'off': False}
DUMP_MIME = BOOLEAN_STATES.get(os.getenv('DUMP_MIME', 'false').lower(), False)
LOGS_PATH = os.getenv('LOGS_PATH', '/var/log/bro/')
DUMP_PATH = os.getenv('DUMP_PATH')
if DUMP_PATH is None:
    try:
        DUMP_PATH = subprocess.check_output(['bro', '-e', 'print(FileExtract::prefix)'],
                                            stderr=subprocess.DEVNULL, encoding='utf-8').strip()
    except subprocess.CalledProcessError:
        DUMP_PATH = './extract_files/'

# log files
FILE = os.path.join(LOGS_PATH, 'processed_dump.log')
FAIL = os.path.join(LOGS_PATH, 'processed_fail.log')


# mimetype class
@dataclasses.dataclass
class MIME:
    content_type: str
    subtype: str
    name: str


# entry class
@dataclasses.dataclass
class Entry:
    name: str
    path: str
    mime: MIME


def print_file(s, file=FILE):
    with open(file, 'at', 1) as LOG:
       print(s, file=LOG)


def process(entry):
    try:
        api_args = API_CFG[entry.mime.content_type][entry.mime.subtype]
        api_path = os.path.join(API_ROOT, entry.mime.content_type, entry.mime.subtype)
    except (KeyError, TypeError):
        api_args = API_CFG['example']
        api_path = os.path.join(API_ROOT, 'example')

    args = [os.path.expandvar(argv) for argv in api_args]
    args.append(entry.path)
    args.append(entry.name)
    args.append(entry.mime.name)

    try:
        subprocess.check_call(args, cwd=api_path)
    except subprocess.CalledProcessError as error:
        print_file(error.args, file=FAIL)
    print_file(entry.path)


def list_dir(path):
    file_list = list()
    if DUMP_MIME:
        for content_type in filter(lambda entry: entry.is_dir(), os.scandir(path)):
            for subtype in filter(lambda entry: entry.is_dir(), os.scandir(content_type.path)):
                mime = MIME(content_type=content_type.name,
                            subtype=subtype.name,
                            name=f'{content_type.name}/{subtype.name}')
                file_list.extend(Entry(path=entry.path, name=entry.name, mime=mime)
                                 for entry in filter(lambda entry: entry.is_file(), os.scandir(subtype.path)))
    else:
        for entry in os.scandir(path):
            content_type, subtype = map(lambda s: s[1:], pathlib.Path(entry.name).suffixes[:2])
            mime = MIME(content_type=content_type,
                        subtype=subtype,
                        name=f'{content_type}/{subtype}')
            file_list.append(Entry(path=entry.path, name=entry.name, mime=mime))
    return file_list


def main():
    # processed log
    processed_file = list()
    if os.path.isfile(FILE):
        with open(FILE) as file:
            processed_file.extend(line.strip() for line in file)

    # main loop
    while True:
        try:
            file_list = sorted(filter(lambda entry: entry.path not in processed_file, list_dir(DUMP_PATH)))
            if file_list:
                if CPU_CNT <= 1:
                    [process(entry) for entry in file_list]  # pylint: disable=expression-not-assigned
                else:
                    multiprocessing.Pool(CPU_CNT).map(process, file_list)
            time.sleep(INTERVAL)
        except KeyboardInterrupt:
            return 0

        print('+ Starting another turn...')
        processed_file.extend(file_list)


if __name__ == '__main__':
    sys.exit(main())
