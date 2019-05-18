# -*- coding: utf-8 -*-
# pylint: disable=import-error, no-name-in-module

import contextlib
import multiprocessing
import os
import queue
import signal
import time
import warnings

from const import INTERVAL, QUEUE

try:
    from sites import HOOK
except ImportError:
    HOOK = list()

###############################################################################

# join flags
JOIN = multiprocessing.Value('B', False)


def join(*args, **kwargs):  # pylint: disable=unused-argument
    JOIN.value = True


# signal handling
signal.signal(signal.SIGUSR1, join)

###############################################################################


class HookWarning(Warning):
    pass


def wrapper(args):
    func, log_name = args
    return func(log_name)


def hook(log_name):
    if HOOK_CPU <= 1:
        [func(log_name) for func in HOOK]  # pylint: disable=expression-not-assigned
    else:
        multiprocessing.Pool(HOOK_CPU).map(wrapper, map(lambda func: (func, log_name), HOOK))  ## pylint: disable=map-builtin-not-iterating


def remote():
    while True:
        try:
            log_name = QUEUE.get_nowait()
            try:
                hook(log_name)
            except BaseException:
                warnings.warn(f'hook execution failed on {log_name!r}', HookWarning)
        except queue.Empty:
            if JOIN.value:
                break
            time.sleep(INTERVAL)


@contextlib.contextmanager
def remote_proc():
    proc = multiprocessing.Process(target=remote)
    proc.start()
    try:
        yield
    finally:
        os.kill(proc.pid, signal.SIGUSR1)
    proc.join()
