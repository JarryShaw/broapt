# -*- coding: utf-8 -*-
# pylint: disable=import-error, no-name-in-module

import multiprocessing
import sys

from compose import docker_compose, register
from const import SERVER_NAME_HOST, SERVER_NAME_PORT
from daemon import app, manager


def run():
    register()
    with docker_compose():
        app.run(host=SERVER_NAME_HOST,
                port=SERVER_NAME_PORT)
    manager.shutdown()


if __name__ == '__main__':
    multiprocessing.freeze_support()
    sys.exit(run())
