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
from sites import hook

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
