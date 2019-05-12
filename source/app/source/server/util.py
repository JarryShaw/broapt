# -*- coding: utf-8 -*-

import contextlib
import functools
import subprocess
import traceback

from .const import DOCKER_COMPOSE, FILE


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


def print_file(s, file=FILE):
    with open(file, 'at', 1) as LOG:
        print(s, file=LOG)


@contextlib.contextmanager
def docker_compose():
    subprocess.check_call(['docker-compose', '--file', DOCKER_COMPOSE, 'up', '--detach'])
    try:
        yield
    finally:
        subprocess.check_call(['docker-compose', '--file', DOCKER_COMPOSE, 'stop'])
