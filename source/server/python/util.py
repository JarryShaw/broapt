# -*- coding: utf-8 -*-
# pylint: disable=import-error, no-name-in-module

import contextlib
import functools
import os
import pathlib
import subprocess
import time
import traceback

from const import DOCKER_COMPOSE, FILE


class APIError(Exception):
    pass


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
    while lock.exists():
        time.sleep(.3)
    with contextlib.suppress(OSError):
        lock.touch()
    with contextlib.suppress(BaseException):
        yield
    with contextlib.suppress(OSError):
        lock.unlink()


def print_file(s, file=FILE):
    with file_lock(file):
        with open(file, 'at', 1) as LOG:
            print(s, file=LOG)


@contextlib.contextmanager
def docker_compose():
    subprocess.check_call(['docker-compose', '--file', DOCKER_COMPOSE, 'up', '--build', '--detach'])
    try:
        yield
    finally:
        subprocess.check_call(['docker-compose', '--file', DOCKER_COMPOSE, 'stop'])


@contextlib.contextmanager
def temp_env(env):
    new_keys = list()
    old_keys = dict()
    for (key, val) in env.items():
        if key in os.environ:
            old_keys[key] = os.environ[key]
        else:
            new_keys.append(key)
        os.environ[key] = val
    try:
        yield
    finally:
        for key in new_keys:
            del os.environ[key]
        os.environ.update(old_keys)
