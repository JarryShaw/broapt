# -*- coding: utf-8 -*-
# pylint: disable=import-error, no-name-in-module

import sys

from const import SERVER_NAME_HOST, SERVER_NAME_PORT
from daemon import app, manager
from util import docker_compose


def run():
    with docker_compose():
        app.run(host=SERVER_NAME_HOST,
                port=SERVER_NAME_PORT)
    manager.shutdown()


if __name__ == '__main__':
    sys.exit(run())
