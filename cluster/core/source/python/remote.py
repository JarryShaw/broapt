# -*- coding: utf-8 -*-
# pylint: disable=import-error, no-name-in-module

import queue
import time

from const import INTERVAL, QUEUE
from sites import hook


def remote():
    while True:
        try:
            log_name = QUEUE.get_nowait()
            hook(log_name)
        except queue.Empty:
            time.sleep(INTERVAL)
