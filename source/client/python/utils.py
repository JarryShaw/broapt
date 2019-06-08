# -*- coding: utf-8 -*-
# pylint: disable=import-error, no-name-in-module

import contextlib
import functools
import math
import os
import pathlib
import time
import traceback

from const import INTERVAL


def suppress(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            func(*args, **kwargs)
        except Exception:
            traceback.print_exc()
    return wrapper


@contextlib.contextmanager
def file_lock(file):
    path = f'{os.path.splitext(file)[0]}.lock'
    lock = pathlib.Path(path)

    interval = 0
    while lock.exists():
        time.sleep(.1)
        interval += .1
        if interval >= INTERVAL:
            break

    with contextlib.suppress(OSError):
        lock.touch()
    with contextlib.suppress(BaseException):
        yield
    with contextlib.suppress(OSError):
        lock.unlink()


@contextlib.contextmanager
def temp_env(env):
    new_keys = list()
    old_keys = dict()
    for (key, val) in env.items():
        if key in os.environ:
            old_keys[key] = os.environ[key]
        else:
            new_keys.append(key)
        os.environ[key] = os.path.expandvars(val)
    try:
        yield
    finally:
        for key in new_keys:
            del os.environ[key]
        os.environ.update(old_keys)


def is_nan(value):
    if value is None:
        return True
    try:
        return math.isnan(value)
    except TypeError:
        return False


def redirect(src, dst, label='unknown'):
    dst_file = open(dst, 'a')
    with open(src) as src_file:
        for line in src_file:
            dst_file.write(f'<{label}> {line}')
    dst_file.close()


def print_file(s, file):
    with file_lock(file):
        with open(file, 'at', 1) as LOG:
            print(s, file=LOG)
