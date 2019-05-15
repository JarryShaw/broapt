# -*- coding: utf-8 -*-
# pylint: disable=import-error, no-name-in-module

import contextlib
import functools
import ipaddress
import json
import math
import os
import pathlib
import time
import traceback

from const import INTERVAL, TIME


class APIWarning(Warning):
    pass


class APIError(Exception):
    pass


class IPAddressJSONEncoder(json.JSONEncoder):

    def default(self, o):  # pylint: disable=method-hidden
        if isinstance(o, ipaddress._IPAddressBase):  # pylint: disable=protected-access
            return str(o)
        return super().default(o)


def is_nan(value):
    if value is None:
        return True
    try:
        return math.isnan(value)
    except TypeError:
        return False


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


def print_file(s, file=TIME):
    with file_lock(file):
        with open(file, 'at', 1) as LOG:
            print(s, file=LOG)


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
