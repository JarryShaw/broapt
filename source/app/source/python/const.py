# -*- coding: utf-8 -*-
# pylint: disable=import-error, no-name-in-module

import os
import pathlib
import subprocess

from .cfgparse import parse

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

# log files
FILE = os.path.join(LOGS_PATH, 'processed_dump.log')
FAIL = os.path.join(LOGS_PATH, 'processed_fail.log')
