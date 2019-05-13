# -*- coding: utf-8 -*-

import time

import requests

from const import EXIT_FAILURE, EXIT_SUCCESS, INTERVAL, SERVER_NAME


def remote(entry, mime, api, cwd):
    while api.locked:
        time.sleep(INTERVAL)
    api.locked = True

    info = dict(
        mime=mime,
        uuid=entry.uuid,
        report=api.report,
        inited=api.inited,
        workdir=api.workdir,
        environ=api.environ,
        install=api.install,
        scripts=api.scripts,
    )

    try:
        resp = requests.post(SERVER_NAME, data=info)
        if resp.json()['reported']:
            return EXIT_SUCCESS
        return EXIT_FAILURE
    except (KeyError, ValueError, requests.RequestException):
        return EXIT_FAILURE
