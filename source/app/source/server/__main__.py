# -*- coding: utf-8 -*-
# pylint: disable=import-error, no-name-in-module

from .util import docker_compose
from .daemon import app, manager

if __name__ == '__main__':
    with docker_compose():
        app.run()
    manager.shutdown()
