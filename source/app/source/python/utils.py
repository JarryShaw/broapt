# -*- coding: utf-8 -*-
# pylint: disable=import-error, no-name-in-module

import contextlib
import os
import pathlib
import time
import traceback

from .const import FILE, INTERVAL


class APIWarning(Warning):
    pass


class APIError(Exception):
    pass


@contextlib.contextmanager
def file_lock(file):
    path = f'{os.path.splitext(file)[0]}.lock'
    lock = pathlib.Path(path)
    while lock.exists():
        time.sleep(INTERVAL)
    lock.touch()
    try:
        yield
    finally:
        lock.unlink()


def print_file(s, file=FILE):
    with file_lock(file):
        with open(file, 'at', 1) as LOG:
            print(s, file=LOG)


def suppress(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            func(*args, **kwargs)
        except APIError:
            raise
        except Exception:
            traceback.print_exc()
    return wrapper
