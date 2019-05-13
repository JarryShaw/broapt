# -*- coding: utf-8 -*-
# pylint: disable=import-error, no-name-in-module

import contextlib
import queue
import time

from const import INTERVAL, QUEUE
from sites import hook


def remote():
    while True:
        with contextlib.suppress(queue.Empty):
            log_name = QUEUE.get_nowait()
            hook(log_name)
        time.sleep(INTERVAL)
