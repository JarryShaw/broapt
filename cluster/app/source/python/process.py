# -*- coding: utf-8 -*-
# pylint: disable=import-error, no-name-in-module

import fnmatch
import os
import shlex
import subprocess
import time
import warnings

from const import (API_DICT, API_LOGS, API_ROOT, DUMP, EXIT_FAILURE, EXIT_SUCCESS, FAIL, INTERVAL,
                   MAX_RETRY)
from remote import remote
from utils import APIError, APIWarning, print_file, suppress, temp_env


def run(command, cwd=None, env=None, mime='example', file='unknown'):
    # prepare log path
    logs_path = os.path.join(API_LOGS, mime)
    os.makedirs(logs_path, exist_ok=True)

    # prepare runtime
    logs = os.path.join(logs_path, file)
    with temp_env(env):
        if isinstance(command, str):
            shell = True
            args = os.path.expandvars(command)
        else:
            shell = False
            args = [os.path.expandvars(arg) for arg in command]
    env_line = f'{os.linesep}#      '.join(f'{key}={shlex.quote(val)}' for (key, val) in env.items())

    suffix = ''
    for retry in range(MAX_RETRY):
        log = logs + suffix
        print_file(f'# open: {time.strftime("%Y-%m-%d-%H-%M-%S")}', file=log)
        print_file(f'# cwd: {cwd}', file=log)
        print_file(f'# env: {env_line}', file=log)
        print_file(f'# args: {args}', file=log)
        try:
            with open(log, 'w') as stdout:
                returncode = subprocess.check_call(args, shell=shell, cwd=cwd, env=env,
                                                   stdout=stdout, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as error:
            print_file(f'# exit: {error.returncode}', file=log)
            print_file(f'# close: {time.strftime("%Y-%m-%d-%H-%M-%S")}', file=log)
            print_file(error.args, file=FAIL)
            suffix = f'_{retry+1}'
            time.sleep(INTERVAL)
            continue
        print_file(f'# exit: {returncode}', file=log)
        print_file(f'# close: {time.strftime("%Y-%m-%d-%H-%M-%S")}', file=log)
        return EXIT_SUCCESS
    return EXIT_FAILURE


def issue(mime):
    if mime == 'example':
        raise APIError(f'default API script execution failed')

    # issue warning
    warnings.warn(f'{mime}: API script execution failed', APIWarning, 2)

    ## remove API entry
    # del API_DICT[mime]
    return EXIT_FAILURE


def init(api, cwd, env, mime, uuid):
    if api.inited.value:
        return EXIT_SUCCESS

    install_log = 1
    for command in api.install:
        log = f'{uuid}-install.{install_log}'
        if run(command, cwd, env, mime, file=log):
            return EXIT_FAILURE
        install_log += 1
    api.inited.value = True
    return EXIT_SUCCESS


def make_cwd(api, entry=None, example=False):
    with temp_env(api.environ):
        workdir = os.path.expandvars(api.workdir)
    def generate_cwd(workdir):
        if os.path.isabs(workdir):
            return workdir
        if example:
            return os.path.join(API_ROOT, 'example', workdir)
        return os.path.join(API_ROOT, entry.mime.media_type, entry.mime.subtype, workdir)
    return os.path.realpath(generate_cwd(workdir))


def make_env(api):
    new_keys = list()
    old_keys = dict()
    for (key, val) in api.environ.items():
        if key in os.environ:
            old_keys[key] = os.environ[key]
        else:
            new_keys.append(key)
        os.environ[key] = os.path.expandvars(val)
    environ = dict(os.environ)

    for key in new_keys:
        del os.environ[key]
    os.environ.update(old_keys)
    return environ


@suppress
def process(entry):  # pylint: disable=inconsistent-return-statements
    print(f'+ Processing {entry.path!r}')

    mime_type = None
    for name in API_DICT.keys():
        if fnmatch.fnmatch(entry.mime.name, name):
            mime_type = name
            break

    if mime_type is not None:
        mime = entry.mime.name
        api = API_DICT[mime_type]
        cwd = make_cwd(api, entry=entry)
    else:
        mime = 'example'
        api = API_DICT['example']
        cwd = make_cwd(api, example=True)

    if api.remote:
        if remote(entry, mime, api):
            return issue(mime)
        return print_file(entry.path, DUMP)

    # set up environ
    env = make_env(api)
    env['BROAPT_PATH'] = entry.path
    env['BROAPT_MIME'] = entry.mime.name

    # run install commands
    if not api.inited.value:
        with api.locked:
            if init(api, cwd, env, mime, entry.uuid):
                return issue(mime)

    # run scripts commands
    scripts_log = 1
    for command in api.scripts:
        log = f'{entry.uuid}-scripts.{scripts_log}'
        if run(command, cwd, env, mime, file=log):
            return issue(mime)
        scripts_log += 1

    # run report command
    log = f'{entry.uuid}-report.1'
    if run(api.report, cwd, env, mime, file=log):
        return issue(mime)
    print_file(entry.path, file=DUMP)
