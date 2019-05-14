# -*- coding: utf-8 -*-
# pylint: disable=import-error, no-name-in-module

from const import SERVER_NAME_HOST, SERVER_NAME_PORT
from daemon import app, manager
from util import docker_compose

if __name__ == '__main__':
    with docker_compose():
        app.run(host=SERVER_NAME_HOST,
                port=SERVER_NAME_PORT)
    manager.shutdown()
