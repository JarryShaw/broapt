# -*- coding: utf-8 -*-
# pylint: disable=import-error, no-name-in-module

import os
import subprocess
import time
import warnings

from const import (API_DICT, API_LOGS, API_ROOT, API_UUID, EXIT_FAILURE, EXIT_SUCCESS,
                   FAIL, INTERVAL, MAX_RETRY)
from utils import APIError, APIWarning, print_file, suppress


def run(command, cwd=None, env=None, mime='example', file='unknown'):
    # prepare log path
    logs_path = os.path.join(API_LOGS, mime)
    os.makedirs(logs_path, exist_ok=True)

    # prepare runtime
    logs = os.path.join(logs_path, file)
    args = os.path.expandvars(command)

    suffix = ''
    for retry in range(MAX_RETRY):
        log = logs + suffix
        print_file(f'# open: {time.ctime()}', file=log)
        print_file(f'# args: {args}', file=log)
        try:
            with open(log, 'at', 1) as stdout:
                returncode = subprocess.check_call(args, shell=True, cwd=cwd, env=env,
                                                   stdout=stdout, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as error:
            print_file(f'# code: {error.returncode}', file=log)
            print_file(f'# exit: {time.ctime()}', file=log)
            print_file(error.args, file=FAIL)
            suffix = f'_{retry+1}'
            time.sleep(INTERVAL)
            continue
        print_file(f'# code: {returncode}', file=log)
        print_file(f'# exit: {time.ctime()}', file=log)
        return EXIT_SUCCESS
    return EXIT_FAILURE


def issue(mime):
    if mime == 'example':
        raise APIError(f'default API script execution failed')

    # issue warning
    warnings.warn(f'{mime}: API script execution failed', APIWarning, 2)

    # remove API entry
    del API_DICT[mime]


def init(api, cwd, env, mime):  # pylint: disable=inconsistent-return-statements
    while api._locked:  # pylint: disable=protected-access
        time.sleep(INTERVAL)
    if api._inited:  # pylint: disable=protected-access
        return

    api._locked = True  # pylint: disable=protected-access
    for command in api.install:
        log = f'{API_UUID}-install.{api.install_log}'
        if run(command, cwd, env, mime, file=log):
            api._locked = False  # pylint: disable=protected-access
            return issue(mime)
        api.install_log += 1
    api._inited = True  # pylint: disable=protected-access
    api._locked = False  # pylint: disable=protected-access


def make_cwd(api, entry=None, example=False):
    def generate_cwd(workdir):
        if os.path.isabs(workdir):
            return workdir

        if example:
            return os.path.join(API_ROOT, 'example', workdir)
        return os.path.join(API_ROOT, entry.mime.media_type, entry.mime.subtype, workdir)
    return os.path.realpath(generate_cwd(api.workdir))


def make_env(api):
    environ = os.environ
    for (env, val) in api.environ.items():
        environ[str(env)] = os.path.expandvars(str(val))
    return environ


@suppress
def process(entry):  # pylint: disable=inconsistent-return-statements
    print(f'+ Processing {entry.path!r}')

    if entry.mime.name in API_DICT:
        mime = entry.mime.name
        api = API_DICT[entry.mime.name]
        cwd = make_cwd(api, entry=entry)
    else:
        mime = 'example'
        api = API_DICT['example']
        cwd = make_cwd(api, example=True)

    # set up environ
    env = make_env(api)
    env['BROAPT_PATH'] = entry.path
    env['BROAPT_MIME'] = entry.mime.name

    # run install commands
    if not api._inited:  # pylint: disable=protected-access
        init(api, cwd, env, mime)

    # run scanner commands
    for command in api.scanner:
        log = f'{API_UUID}-scanner.{api.scanner_log}'
        if run(command, cwd, env, mime, file=log):
            return issue(mime)
        api.scanner_log += 1

    # run report command
    log = f'{API_UUID}-report.1'
    if run(api.report, cwd, env, mime, file=log):
        return issue(mime)
    print_file(entry.path)
