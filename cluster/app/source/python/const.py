# -*- coding: utf-8 -*-
# pylint: disable=import-error, no-name-in-module

import os
import pathlib
import subprocess

from cfgparser import parse

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
    INTERVAL = float(os.getenv('BROAPT_APP_INTERVAL'))
except (TypeError, ValueError):
    INTERVAL = 10

# command retry
try:
    MAX_RETRY = int(os.getenv('BROAPT_MAX_RETRY'))
except (TypeError, ValueError):
    MAX_RETRY = 3

# macros
EXIT_SUCCESS = 0
EXIT_FAILURE = 1

# Bro config
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

# remote server
SERVER_NAME_HOST = os.getenv('SERVER_NAME_HOST', 'localhost')
try:
    SERVER_NAME_PORT = int(os.getenv('SERVER_NAME_PORT'))
except (TypeError, ValueError):
    SERVER_NAME_PORT = 5000
SERVER_NAME = f'http://{SERVER_NAME_HOST}:{SERVER_NAME_PORT}/api/v1.0/scan'

# log files
DUMP = os.path.join(LOGS_PATH, 'dump.log')
FAIL = os.path.join(LOGS_PATH, 'fail.log')
