# -*- coding: utf-8 -*-
# pylint: disable=import-error, no-name-in-module

import contextlib
import json
import multiprocessing
import signal
import subprocess
import time

import flask

from const import DOCKER_COMPOSE, INTERVAL, KILL_SIGNAL

# running flag
UP_FLAG = multiprocessing.Value('B', True)

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


def watch_container():
    container_id = subprocess.check_output(['docker-compose', '--file', DOCKER_COMPOSE,
                                            'ps', '--quiet'], encoding='utf-8').strip()

    while UP_FLAG.value:
        inspect = subprocess.check_output(['docker', 'container', 'inspect',
                                           container_id], encoding='utf-8').strip()
        # running / paused / exited
        status = json.loads(inspect)[0]['State']['Status'].casefold()
        if status == 'paused':
            subprocess.check_call(['docker-compose', '--file', DOCKER_COMPOSE, 'unpause'])
        if status == 'exited':
            subprocess.check_call(['docker-compose', '--file', DOCKER_COMPOSE, 'up', '--detach'])
        time.sleep(INTERVAL)


@contextlib.contextmanager
def docker_compose():
    start_container()
    proc = multiprocessing.Process(target=watch_container)
    proc.start()
    try:
        yield
    except BaseException:
        pass
    UP_FLAG.value = False
    proc.join()
    stop_container()


def flask_exit(signum=None, frame=None):  # pylint: disable=unused-argument
    if signum is not None:
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
