# -*- coding: utf-8 -*-
# pylint: disable=import-error, no-name-in-module

import contextlib
import functools
import io
import os
import sys

from const import LOGS_PATH, SERVER_NAME_HOST, SERVER_NAME_PORT
from daemon import app, manager
from util import docker_compose


def redirect(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        # redirect stdout
        if sys.stdout.isatty():
            stdout = io.StringIO()
            redirect_stdout = contextlib.nullcontext()
        else:
            stdout = open(os.path.join(LOGS_PATH, 'stdout.log'), 'w')
            redirect_stdout = contextlib.redirect_stdout(stdout)

        # redirect stderr
        if sys.stderr.isatty():
            stderr = io.StringIO()
            redirect_stderr = contextlib.nullcontext()
        else:
            stderr = open(os.path.join(LOGS_PATH, 'stderr.log'), 'w')
            redirect_stderr = contextlib.redirect_stderr(stderr)

        # call function
        with redirect_stdout:
            with redirect_stderr:
                return func(*args, **kwargs)

        # close stdout & stderr
        stdout.close()
        stderr.close()
    return wrapper


@redirect
def run():
    with docker_compose():
        app.run(host=SERVER_NAME_HOST,
                port=SERVER_NAME_PORT)
    manager.shutdown()


if __name__ == '__main__':
    sys.exit(run())
