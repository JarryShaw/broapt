# -*- coding: utf-8 -*-
# pylint: disable=import-error, no-name-in-module

import multiprocessing
import os

from compose import (BOOLEAN_STATES, DUMP_PATH, LOGS_PATH,  # pylint: disable=unused-import
                     MIME_MODE, PCAP_PATH, ROOT)

# limit on CPU
try:
    CPU_CNT = int(os.getenv('BROAPT_CORE_CPU'))
except (ValueError, TypeError):
    if os.name == 'posix' and 'SC_NPROCESSORS_CONF' in os.sysconf_names:
        CPU_CNT = os.sysconf('SC_NPROCESSORS_CONF')
    elif 'sched_getaffinity' in os.__all__:
        CPU_CNT = len(os.sched_getaffinity(0))  # pylint: disable=E1101
    else:
        CPU_CNT = os.cpu_count() or 1

# sleep interval
try:
    INTERVAL = float(os.getenv('BROAPT_CORE_INTERVAL'))
except (TypeError, ValueError):
    INTERVAL = 10

## run Bro in bare mode
BARE_MODE = BOOLEAN_STATES.get(os.getenv('BROAPT_BARE_MODE', 'false').casefold(), False)
## run Bro with `-C` option
NO_CHKSUM = BOOLEAN_STATES.get(os.getenv('BROAPT_NO_CHKSUM', 'true').casefold(), True)

# log files
FILE = os.path.join(LOGS_PATH, 'file.log')
TIME = os.path.join(LOGS_PATH, 'time.log')
STDOUT = os.path.join(LOGS_PATH, 'stdout.log')
STDERR = os.path.join(LOGS_PATH, 'stderr.log')

# log queue
QUEUE = multiprocessing.Queue()

# hook limit for CPU
try:
    HOOK_CPU = int(os.getenv('BROAPT_HOOK_CPU'))
except (TypeError, ValueError):
    HOOK_CPU = 1
