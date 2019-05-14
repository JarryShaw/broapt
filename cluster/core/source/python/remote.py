# -*- coding: utf-8 -*-
# pylint: disable=import-error, no-name-in-module

import queue
import time
import warnings

from const import INTERVAL, QUEUE
from sites import hook


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
            time.sleep(INTERVAL)
