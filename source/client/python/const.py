# -*- coding: utf-8 -*-
# pylint: disable=import-error, no-name-in-module

import multiprocessing
import os
import re

from cfgparser import parse
from compose import (BOOLEAN_STATES, DUMP_PATH, LOGS_PATH,  # pylint: disable=unused-import
                     MIME_MODE, PCAP_PATH, ROOT)

# limit on CPU
try:
    CPU_CNT = int(os.getenv('BROAPT_CPU'))
except (ValueError, TypeError):
    if os.name == 'posix' and 'SC_NPROCESSORS_CONF' in os.sysconf_names:
        CPU_CNT = os.sysconf('SC_NPROCESSORS_CONF')
    elif 'sched_getaffinity' in os.__all__:
        CPU_CNT = len(os.sched_getaffinity(0))  # pylint: disable=E1101
    else:
        CPU_CNT = os.cpu_count() or 1

# sleep interval
try:
    INTERVAL = float(os.getenv('BROAPT_INTERVAL'))
except (TypeError, ValueError):
    INTERVAL = 10

## run Bro in bare mode
BARE_MODE = BOOLEAN_STATES.get(os.getenv('BROAPT_BARE_MODE', 'false').casefold(), False)
## run Bro with `-C` option
NO_CHKSUM = BOOLEAN_STATES.get(os.getenv('BROAPT_NO_CHKSUM', 'true').casefold(), True)

# log files
FILE = os.path.join(LOGS_PATH, 'processed_file.log')
TIME = os.path.join(LOGS_PATH, 'processed_time.log')
INFO = os.path.join(LOGS_PATH, 'processed_info.log')

# command retry
try:
    MAX_RETRY = int(os.getenv('BROAPT_MAX_RETRY'))
except (TypeError, ValueError):
    MAX_RETRY = 3

# macros
EXIT_SUCCESS = 0
EXIT_FAILURE = 1

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
DUMP = os.path.join(LOGS_PATH, 'processed_dump.log')
FAIL = os.path.join(LOGS_PATH, 'processed_fail.log')

# file name regex
FILE_REGEX = re.compile(r'''
    # protocol prefix
    (?P<protocol>DTLS|FTP_DATA|HTTP|IRC_DATA|SMTP|\S+)
    -
    # file UID
    (?P<fuid>F\w+)
    \.
    # media-type
    (?P<media_type>application|audio|example|font|image|message|model|multipart|text|video|\S+)
    \.
    # subtype
    (?P<subtype>\S+)
    \.
    # file extension
    (?P<extension>\S+)
''', re.IGNORECASE | re.VERBOSE)

# MIME type regex
MIME_REGEX = re.compile(r'''
    # media-type
    (?P<media_type>application|audio|example|font|image|message|model|multipart|text|video|\S+)
    /
    # subtype
    (?P<subtype>\S+)
''', re.VERBOSE | re.IGNORECASE)

# hook limit for CPU
try:
    HOOK_CPU = int(os.getenv('BROAPT_HOOK_CPU'))
except (TypeError, ValueError):
    HOOK_CPU = 1

# scan limit for CPU
try:
    SCAN_CPU = int(os.getenv('BROAPT_SCAN_CPU'))
except (TypeError, ValueError):
    SCAN_CPU = 10

# queues
QUEUE_LOGS = multiprocessing.Queue()
QUEUE_DUMP = multiprocessing.Queue()
