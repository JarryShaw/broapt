# -*- coding: utf-8 -*-
# pylint: disable=import-error, no-name-in-module

import os

from cli import parse_args

# parse arguments
_args = parse_args()

# CLI arguments
KILL_SIGNAL = _args.signal
SERVER_NAME_HOST = _args.host
SERVER_NAME_PORT = _args.port
DOCKER_COMPOSE = _args.docker_compose
DUMP_PATH = _args.dump_path
LOGS_PATH = _args.logs_path
API_LOGS = _args.api_logs
API_ROOT = _args.api_root
INTERVAL = _args.interval
MAX_RETRY = _args.max_retry

# macros
EXIT_SUCCESS = 0
EXIT_FAILURE = 1

# log files
FILE = os.path.join(LOGS_PATH, 'dump.log')
FAIL = os.path.join(LOGS_PATH, 'fail.log')

# unset args
del _args
