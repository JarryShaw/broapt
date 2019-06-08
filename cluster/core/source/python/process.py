# -*- coding: utf-8 -*-
# pylint: disable=import-error, no-name-in-module

import contextlib
import glob
import multiprocessing
import os
import pathlib
import shutil
import subprocess
import time
import uuid
import warnings

from compose import file_salt
from const import (BARE_MODE, DUMP_PATH, FILE, LOGS_PATH, NO_CHKSUM, QUEUE, ROOT, STDERR, STDOUT,
                   TIME)
from logparser import parse
from utils import is_nan, print_file, redirect, suppress

# synchronize locks
SALT_LOCK = multiprocessing.Lock()
STDOUT_LOCK = multiprocessing.Lock()
STDERR_LOCK = multiprocessing.Lock()


class ExtractWarning(Warning):
    pass


def communicate(log_root):
    log_file = os.path.join(log_root, 'files.log')
    if not os.path.isfile(log_file):
        return

    LOG_FILE = parse(log_file)
    for line in LOG_FILE.context.itertuples():
        if is_nan(getattr(line, 'extracted', None)):
            continue

        local_name = line.extracted
        dump_path = os.path.join(DUMP_PATH, local_name)
        if not os.path.exists(dump_path):
            warnings.warn(f'No such file or directory: {local_name!r}', ExtractWarning)
            return


@suppress
def process(file):
    print_file(f'+ Working on PCAP: {file!r}', TIME)
    print(f'+ Working on PCAP: {file!r}')

    stem = pathlib.Path(file).stem
    uid = uuid.uuid4()

    dest_stem = f'{stem}-{uid}'
    with SALT_LOCK:
        file_salt(uid)

    env = os.environ
    env['BRO_LOG_SUFFIX'] = f'{uid}.log'
    env['BROAPT_PCAP'] = dest_stem

    args = ['bro']
    if BARE_MODE:
        args.append('--bare-mode')
    if NO_CHKSUM:
        args.append('--no-checksums')
    args.extend(['--readfile', file, os.path.join(ROOT, 'scripts')])

    start = time.time()
    stdout = open(f'stdout.{uid}.log', 'at', 1)
    stderr = open(f'stderr.{uid}.log', 'at', 1)
    print(f'+ {" ".join(args)}', file=stdout)
    print(f'+ {" ".join(args)}', file=stderr)
    try:
        subprocess.check_call(args, env=env, stdout=stdout, stderr=stderr)
    except subprocess.CalledProcessError:
        print_file(f'+ Failed on PCAP: {file!r}', TIME)
    stdout.close()
    stderr.close()
    end = time.time()

    with STDOUT_LOCK:
        redirect(src=stdout.name, dst=STDOUT, label=dest_stem)
    with STDERR_LOCK:
        redirect(src=stderr.name, dst=STDERR, label=dest_stem)

    dest = os.path.join(LOGS_PATH, dest_stem)
    os.makedirs(dest, exist_ok=True)

    for log in glob.glob(f'*.{uid}.log'):
        with contextlib.suppress(OSError):
            shutil.move(log, os.path.join(dest, log.replace(f'.{uid}.log', '.log')))
    communicate(dest)

    print_file(f'+ Bro processing: {end-start} seconds', TIME)
    print_file(file, file=FILE)
    QUEUE.put(dest_stem)
