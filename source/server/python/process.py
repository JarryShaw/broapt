# -*- coding: utf-8 -*-
# pylint: disable=import-error, no-name-in-module

import os
import shlex
import subprocess
import time

from const import (API_LOGS, API_ROOT, DUMP_PATH, EXIT_FAILURE, EXIT_SUCCESS, FAIL, INTERVAL,
                   MAX_RETRY)
from util import print_file, suppress, temp_env


def make_env(info):
    new_keys = list()
    old_keys = dict()
    for (key, val) in info.environ.items():
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


def make_cwd(info):
    with temp_env(info.environ):
        workdir = os.path.expandvars(info.workdir)
    def generate_cwd(workdir):
        if os.path.isabs(workdir):
            return workdir
        return os.path.join(API_ROOT, info.mime, workdir)
    return os.path.realpath(generate_cwd(workdir))


def run(command, info, file='unknown'):
    # prepare log path
    logs_path = os.path.join(API_LOGS, info.mime)
    os.makedirs(logs_path, exist_ok=True)

    # prepare runtime
    logs = os.path.join(logs_path, file)
    with temp_env(info.environ):
        if isinstance(command, str):
            shell = True
            args = os.path.expandvars(command)
        else:
            shell = False
            args = [os.path.expandvars(arg) for arg in command]
    env_line = f'{os.linesep}#      '.join(f'{key}={shlex.quote(val)}' for (key, val) in info.environ.items())

    suffix = ''
    for retry in range(MAX_RETRY):
        log = logs + suffix
        print_file(f'# open: {time.strftime("%Y-%m-%d-%H-%M-%S")}', file=log)
        print_file(f'# cwd: {info.workdir}', file=log)
        print_file(f'# env: {env_line}', file=log)
        print_file(f'# args: {args}', file=log)
        try:
            with open(log, 'at', 1) as stdout:
                returncode = subprocess.check_call(args, shell=shell, cwd=info.workdir, env=info.environ,
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


def init(info):
    install_log = 1
    for command in info.install:
        log = f'{info.uuid}-install.{install_log}'
        if run(command, info, file=log):
            return EXIT_FAILURE
        install_log += 1
    info.inited.value = True
    return EXIT_SUCCESS


@suppress
def process(info):
    print(f'+ Processing {info.name!r}')

    # set up environ
    env = make_env(info)
    env['BROAPT_PATH'] = os.path.join(DUMP_PATH, info.name)
    env['BROAPT_MIME'] = info.mime

    info.environ = make_env(info)
    info.workdir = make_cwd(info)

    # run install commands
    if not info.inited.value:
        with info.locked:
            if init(info):
                return False

    # run scripts commands
    scripts_log = 1
    for command in info.scripts:
        log = f'{info.uuid}-scripts.{scripts_log}'
        if run(command, info, file=log):
            return False
        scripts_log += 1

    # run report command
    log = f'{info.uuid}-report.1'
    if run(info.report, info, file=log):
        return False
    return True
