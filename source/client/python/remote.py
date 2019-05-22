# -*- coding: utf-8 -*-
# pylint: disable=import-error, no-name-in-module

import contextlib
import multiprocessing
import os
import queue
import signal
import time
import traceback
import warnings

from const import DUMP_PATH, HOOK_CPU, INTERVAL, QUEUE_DUMP, QUEUE_LOGS, SCAN_CPU
from scan import lookup, scan

try:
    from sites import HOOK
except ImportError:
    HOOK = list()

try:
    from sites import EXIT
except ImportError:
    EXIT = list()

###############################################################################

# join flags
JOIN_DUMP = multiprocessing.Value('B', False)
JOIN_LOGS = multiprocessing.Value('B', False)


def join_dump(*args, **kwargs):  # pylint: disable=unused-argument
    JOIN_DUMP.value = True


def join_logs(*args, **kwargs):  # pylint: disable=unused-argument
    JOIN_LOGS.value = True


# signal handling
signal.signal(signal.SIGUSR1, join_dump)
signal.signal(signal.SIGUSR2, join_logs)

###############################################################################


class HookWarning(Warning):
    pass


def wrapper_logs(args):
    func, log_name = args
    return func(log_name)


def wrapper_func(func):
    return func()


def hook(log_name):
    if HOOK_CPU <= 1:
        [func(log_name) for func in HOOK]  # pylint: disable=expression-not-assigned
    else:
        multiprocessing.Pool(HOOK_CPU).map(wrapper_logs, map(lambda func: (func, log_name), HOOK))  ## pylint: disable=map-builtin-not-iterating


def remote_logs():  # pylint: disable=inconsistent-return-statements
    if len(HOOK) < 1:
        return
    while True:
        try:
            log_name = QUEUE_LOGS.get_nowait()
            try:
                hook(log_name)
            except Exception:
                traceback.print_exc()
                warnings.warn(f'hook execution failed on {log_name!r}', HookWarning)
        except queue.Empty:
            if JOIN_DUMP.value:
                break
        time.sleep(INTERVAL)
    if HOOK_CPU <= 1:
        [func() for func in EXIT]  # pylint: disable=expression-not-assigned
    else:
        multiprocessing.Pool(HOOK_CPU).map(wrapper_func, EXIT)


def remote_dump():
    max_list = SCAN_CPU ** 2
    while True:
        dump_list = list()
        for _ in range(max_list):
            try:
                dump = QUEUE_DUMP.get_nowait()
                dump_list.append(dump)
            except queue.Empty:
                break
        if dump_list:
            if SCAN_CPU <= 1:
                [scan(dump) for dump in dump_list]  # pylint: disable=expression-not-assigned
            else:
                multiprocessing.Pool(SCAN_CPU).map(scan, dump_list)
        if JOIN_DUMP.value:
            break
        time.sleep(INTERVAL)


@contextlib.contextmanager
def remote_proc():
    # check for remaining extracted files
    [QUEUE_DUMP.put(file) for file in lookup(DUMP_PATH)]  # pylint: disable=expression-not-assigned

    # start main loop
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
