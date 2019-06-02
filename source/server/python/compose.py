# -*- coding: utf-8 -*-
# pylint: disable=import-error, no-name-in-module

import contextlib
import signal
import subprocess

import flask

from const import DOCKER_COMPOSE, KILL_SIGNAL

# compat for signal
if not hasattr(signal, 'Signals'):
    signal.Signals = type(signal.SIGUSR1)


def start_container():
    subprocess.check_call(['docker-compose', '--file', DOCKER_COMPOSE, 'up', '--build', '--detach'])


def stop_container():
    try:
        subprocess.check_call(['docker-compose', '--file', DOCKER_COMPOSE, 'stop'])
    except subprocess.CalledProcessError:
        subprocess.check_call(['docker-compose', '--file', DOCKER_COMPOSE, 'kill'])
    subprocess.check_call(['docker', 'system', 'prune', '--volumes', '-f'])


@contextlib.contextmanager
def docker_compose():
    start_container()
    try:
        yield
    except BaseException:
        pass
    stop_container()


def flask_exit(signum=None, frame=None):  # pylint: disable=unused-argument
    print('Signal handler called with signal', signal.Signals(signum))
    shutdown = flask.request.environ.get('werkzeug.server.shutdown')
    if shutdown is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    shutdown()


# signal.signal(signal.SIGHUP, flask_exit)
# signal.signal(signal.SIGINT, flask_exit)
# signal.signal(signal.SIGQUIT, flask_exit)
# signal.signal(signal.SIGABRT, flask_exit)
# signal.signal(signal.SIGKILL, flask_exit)
# signal.signal(signal.SIGALRM, flask_exit)
# signal.signal(signal.SIGTERM, flask_exit)


def register():
    signal.signal(signal.Signals(KILL_SIGNAL), flask_exit)
