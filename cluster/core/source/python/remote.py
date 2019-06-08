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

from const import INTERVAL, QUEUE, HOOK_CPU

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
JOIN = multiprocessing.Value('B', False)


def join(*args, **kwargs):  # pylint: disable=unused-argument
    JOIN.value = True


# signal handling
signal.signal(signal.SIGUSR1, join)

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


def remote():  # pylint: disable=inconsistent-return-statements
    if len(HOOK) < 1:  # pylint: disable=len-as-condition
        return
    while True:
        try:
            log_name = QUEUE.get_nowait()
            try:
                hook(log_name)
            except Exception:
                traceback.print_exc()
                warnings.warn(f'hook execution failed on {log_name!r}', HookWarning)
        except queue.Empty:
            if JOIN.value:
                break
        time.sleep(INTERVAL)
    if HOOK_CPU <= 1:
        [func() for func in EXIT]  # pylint: disable=expression-not-assigned
    else:
        multiprocessing.Pool(HOOK_CPU).map(wrapper_func, EXIT)


@contextlib.contextmanager
def remote_proc():
    proc = multiprocessing.Process(target=remote)
    proc.start()
    try:
        yield
    except BaseException:
        traceback.print_exc()
    finally:
        os.kill(proc.pid, signal.SIGUSR1)
    proc.join()
