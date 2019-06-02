# -*- coding: utf-8 -*-
# pylint: disable=import-error, no-name-in-module

import contextlib
import signal
import subprocess

from const import DOCKER_COMPOSE, KILL_SIGNAL

# compat for signal
if not hasattr(signal, 'Signals'):
    signal.Signals = type(signal.SIGUSR1)


def start_container(signum=None, frame=None):  # pylint: disable=unused-argument
    subprocess.check_call(['docker-compose', '--file', DOCKER_COMPOSE, 'up', '--build', '--detach'])


def stop_container(signum=None, frame=None):  # pylint: disable=unused-argument
    if signum is not None:
        print('Signal handler called with signal', signal.Signals(signum))
    subprocess.check_call(['docker-compose', '--file', DOCKER_COMPOSE, 'stop'])


@contextlib.contextmanager
def docker_compose():
    start_container()
    try:
        yield
    except BaseException:
        pass
    stop_container()


# signal.signal(signal.SIGHUP, stop_container)
# signal.signal(signal.SIGINT, stop_container)
# signal.signal(signal.SIGQUIT, stop_container)
# signal.signal(signal.SIGABRT, stop_container)
# signal.signal(signal.SIGKILL, stop_container)
# signal.signal(signal.SIGALRM, stop_container)
# signal.signal(signal.SIGTERM, stop_container)


def register():
    signal.signal(signal.Signals(KILL_SIGNAL), stop_container)
