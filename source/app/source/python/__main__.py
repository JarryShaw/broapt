# -*- coding: utf-8 -*-

import dataclasses
import functools
import multiprocessing
import os
import pathlib
import subprocess
import sys
import time
import warnings

from cfgparser import parse  # pylint: disable=import-error

# repo root path
ROOT = str(pathlib.Path(__file__).parents[1].resolve())

# limit on CPU
try:
    CPU_CNT = int(os.getenv('BROAPT_APP_CPU'))
except (ValueError, TypeError):
    if os.name == 'posix' and 'SC_NPROCESSORS_CONF' in os.sysconf_names:
        CPU_CNT = os.sysconf('SC_NPROCESSORS_CONF')
    elif 'sched_getaffinity' in os.__all__:
        CPU_CNT = len(os.sched_getaffinity(0))  # pylint: disable=E1101
    else:
        CPU_CNT = os.cpu_count() or 1

# sleep interval
try:
    INTERVAL = int(os.getenv('BROAPT_APP_INTERVAL'))
except (TypeError, ValueError):
    INTERVAL = 10

# Bro config
BOOLEAN_STATES = {'1': True, '0': False,
                  'yes': True, 'no': False,
                  'true': True, 'false': False,
                  'on': True, 'off': False}
MIME_MODE = BOOLEAN_STATES.get(os.getenv('BROAPT_MIME_MODE', 'false').lower(), False)
LOGS_PATH = os.getenv('BROAPT_LOGS_PATH', '/var/log/bro/')
DUMP_PATH = os.getenv('BROAPT_DUMP_PATH')
if DUMP_PATH is None:
    try:
        DUMP_PATH = subprocess.check_output(['bro', '-e', 'print(FileExtract::prefix)'],
                                            stderr=subprocess.DEVNULL, encoding='utf-8').strip()
    except subprocess.CalledProcessError:
        DUMP_PATH = './extract_files/'

# parse API
API_ROOT = os.getenv('BROAPT_API_ROOT', '/api/')
API_LOGS = os.getenv('BROAPT_API_LOGS', '/var/log/bro/api/')
API_DICT = parse(API_ROOT)

# log files
FILE = os.path.join(LOGS_PATH, 'processed_dump.log')
FAIL = os.path.join(LOGS_PATH, 'processed_fail.log')


# mimetype class
@dataclasses.dataclass
class MIME:
    media_type: str
    subtype: str
    name: str


# entry class
@functools.total_ordering
@dataclasses.dataclass
class Entry:
    path: str
    mime: MIME

    def __lt__(self, value):
        return self.path < value.path


def print_file(s, file=FILE):
    with open(file, 'at', 1) as LOG:
        print(s, file=LOG)


class APIWarning(Warning):
    pass


class APIError(Exception):
    pass


def run(command, cwd=None, env=None, file='unknown'):
    # prepare log path
    logs_path = os.path.join(API_LOGS, env['BROAPT_MIME'])
    os.makedirs(logs_path, exist_ok=True)

    # prepare runtime
    log = os.path.join(logs_path, file)
    args = os.path.expandvars(command)

    print_file(f'# time: {time.ctime()}', file=log)
    print_file(f'# args: {args}', file=log)

    try:
        with open(log, 'at', 1) as stdout:
            subprocess.check_call(args, shell=True, cwd=cwd, env=env,
                                  stdout=stdout, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as error:
        print_file(error.args, file=FAIL)
        return True
    return False


def issue(mime):
    if mime == 'example':
        raise APIError(f'default API script execution failed')

    # issue warning
    warnings.warn(f'{mime}: API script execution failed', APIWarning, 2)

    # remove API entry
    del API_DICT[mime]


def process(entry):
    if entry.mime.name in API_DICT:
        mime = entry.mime.name
        api = API_DICT[entry.mime]
        cwd = os.path.join(API_ROOT, entry.mime.media_type, entry.mime.subtype, api.workdir)
    else:
        mime = 'example'
        api = API_DICT['example']
        cwd = os.path.join(API_ROOT, 'example', api.workdir)

    # set up environ
    env = os.environ
    env.update(api.environ)
    env['BROAPT_PATH'] = entry.path
    env['BROAPT_MIME'] = entry.mime.name

    # run install commands
    if not api._inited:  # pylint: disable=protected-access
        for command in api.install:
            log = f'install.{api.install_log}'
            if run(command, cwd, env, file=log):
                issue(mime)
                return
            api.install_log += 1
        api._inited = True  # pylint: disable=protected-access

    # run scripts commands
    for command in api.scripts:
        log = f'scripts.{api.scripts_log}'
        if run(command, cwd, env, file=log):
            issue(mime)
            return
        api.scripts_log += 1

    print_file(entry.path)


def list_dir(path):
    file_list = list()
    if MIME_MODE:
        for media_type in filter(lambda entry: entry.is_dir(), os.scandir(path)):
            for subtype in filter(lambda entry: entry.is_dir(), os.scandir(media_type.path)):
                mime = MIME(media_type=media_type.name,
                            subtype=subtype.name,
                            name=f'{media_type.name}/{subtype.name}'.lower())
                file_list.extend(Entry(path=entry.path, mime=mime)
                                 for entry in filter(lambda entry: entry.is_file(), os.scandir(subtype.path)))
    else:
        for entry in os.scandir(path):
            media_type, subtype = map(lambda s: s[1:], pathlib.Path(entry.name).suffixes[:2])
            mime = MIME(media_type=media_type,
                        subtype=subtype,
                        name=f'{media_type}/{subtype}'.lower())
            file_list.append(Entry(path=entry.path, mime=mime))
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
