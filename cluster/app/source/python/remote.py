# -*- coding: utf-8 -*-
# pylint: disable=import-error, no-name-in-module

import os

import requests

from const import DUMP_PATH, EXIT_FAILURE, EXIT_SUCCESS, SERVER_NAME


def remote(entry, mime, api):
    info = dict(
        name=os.path.relpath(entry.path, DUMP_PATH),
        mime=mime,
        uuid=entry.uuid,
        report=api.report,
        shared=api.shared,
        inited=api.inited.value,
        workdir=api.workdir,
        environ=api.environ,
        install=api.install,
        scripts=api.scripts,
    )

    try:
        resp = requests.post(SERVER_NAME, json=info)
        json = resp.json()
        api.inited.value = json['inited']
        if json['reported']:
            api.inited.value = True
            return EXIT_SUCCESS
        return EXIT_FAILURE
    except (KeyError, ValueError, requests.RequestException):
        return EXIT_FAILURE
