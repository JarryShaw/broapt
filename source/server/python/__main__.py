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

# resolve compatibility issue
if not hasattr(contextlib, 'nullcontext'):
    class nullcontext(contextlib.AbstractContextManager):
        """Context manager that does no additional processing.

        Used as a stand-in for a normal context manager, when a particular
        block of code is only sometimes used with a normal context manager:

        cm = optional_cm if condition else nullcontext()
        with cm:
            # Perform operation, using optional_cm if condition is True
        """

        def __init__(self, enter_result=None):
            self.enter_result = enter_result

        def __enter__(self):
            return self.enter_result

        def __exit__(self, *excinfo):  # pylint: disable=arguments-differ
            pass

    contextlib.nullcontext = nullcontext


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
