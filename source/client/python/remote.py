# -*- coding: utf-8 -*-
# pylint: disable=import-error, no-name-in-module

import contextlib
import multiprocessing
import os
import queue
import signal
import time
import warnings

from .const import INTERVAL, QUEUE_DUMP, QUEUE_LOGS
from .scan import scan
from .sites import hook

###############################################################################

# join flags
JOIN_DUMP = multiprocessing.Value('B', False)
JOIN_LOGS = multiprocessing.Value('B', False)


def join_dump(*args):
    JOIN_DUMP.value = True


def join_logs(*args):
    JOIN_LOGS.value = True


# signal handling
signal.signal(SIGUSR1, join_dump)
signal.signal(SIGUSR2, join_logs)

###############################################################################


class HookWarning(Warning):
    pass


def remote_logs():
    while True:
        try:
            log_name = QUEUE_LOGS.get_nowait()
            try:
                hook(log_name)
            except BaseException:
                warnings.warn(f'hook execution failed on {log_name!r}', HookWarning)
        except queue.Empty:
            if JOIN_DUMP.value:
                break
            time.sleep(INTERVAL)


def remote_dump():
    while True:
        try:
            scan(QUEUE_DUMP.get_nowait())
        except queue.Empty:
            if JOIN_DUMP.value:
                break
            time.sleep(INTERVAL)


@contextlib.contextmanager
def remote_proc():
    proc_dump = multiprocessing.Process(target=remote_dump)
    proc_logs = multiprocessing.Process(target=remote_logs)
    proc_dump.start()
    proc_logs.start()
    try:
        yield
    finally:
        os.kill(proc_dump.pid, signal.SIGUSR1)
        os.kill(proc_logs.pid, signal.SIGUSR2)
    proc_dump.join()
    proc_logs.join()
