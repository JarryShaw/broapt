# -*- coding: utf-8 -*-
# pylint: disable=no-member

import builtins
import contextlib
import multiprocessing
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import time
import warnings

import magic

# limit on CPU
try:
    CPU_CNT = int(os.getenv('CORE_CPU'))
except (ValueError, TypeError):
    if os.name == 'posix' and 'SC_NPROCESSORS_CONF' in os.sysconf_names:
        CPU_CNT = os.sysconf('SC_NPROCESSORS_CONF')
    elif 'sched_getaffinity' in os.__all__:
        CPU_CNT = len(os.sched_getaffinity(0))  # pylint: disable=E1101
    else:
        CPU_CNT = os.cpu_count() or 1

# repo root path
ROOT = str(pathlib.Path(__file__).parents[1].resolve())

# PCAP magic numbers
PCAP_MGC = (b'\xa1\xb2\x3c\x4d',
            b'\xa1\xb2\xc3\xd4',
            b'\x4d\x3c\xb2\xa1',
            b'\xd4\xc3\xb2\xa1',
            b'\x0a\x0d\x0d\x0a')

# Bro config
BOOLEAN_STATES = {'1': True, '0': False,
                  'yes': True, 'no': False,
                  'true': True, 'false': False,
                  'on': True, 'off': False}
DUMP_MIME = BOOLEAN_STATES.get(os.getenv('DUMP_MIME', 'true').strip().lower(), True)
DUMP_PATH = os.getenv('DUMP_PATH', '/dump/').strip()
PCAP_PATH = os.getenv('PCAP_PATH', '/pcap/').strip()
LOGS_PATH = os.getenv('LOGS_PATH', '/var/log/bro/').strip()

# update Bro scripts
MIME_REGEX = re.compile(r'(?P<prefix>\s*redef mime\s*=\s*)[TF](?P<suffix>\s*;\s*)')
PATH_REGEX = re.compile(r'(?P<prefix>\s*redef path\s*=\s*").*?(?P<suffix>"\s*;\s*)')
LOGS_REGEX = re.compile(r'(?P<prefix>\s*redef logs\s*=\s*").*?(?P<suffix>"\s*;\s*)')
context = list()
with open(os.path.join(ROOT, 'scripts', 'config.bro')) as config:
    for line in config:
        line = MIME_REGEX.sub(rf'\g<prefix>{"T" if DUMP_MIME else "F"}\g<suffix>', line)
        line = PATH_REGEX.sub(rf'\g<prefix>{DUMP_PATH}\g<suffix>', line)
        line = LOGS_REGEX.sub(rf'\g<prefix>{os.path.join(LOGS_PATH, "processed_mime.log")}\g<suffix>', line)
        context.append(line)
with open(os.path.join(ROOT, 'scripts', 'config.bro'), 'w') as config:
    config.writelines(context)

# log files
FILE = os.path.join(LOGS_PATH, 'processed_file.log')
TIME = os.path.join(LOGS_PATH, 'processed_time.log')

# sleep interval
try:
    INTERVAL = int(os.getenv('CORE_INT'))
except (TypeError, ValueError):
    INTERVAL = 10


def print(s, file=TIME):  # pylint: disable=redefined-builtin
    with open(file, 'at', 1) as LOG:
        builtins.print(s, file=LOG)
    builtins.print(s, file=sys.stdout)


def is_pcap(file):
    with contextlib.suppress(Exception):
        mime = magic.from_file(file, mime=True)
        if mime == 'application/vnd.tcpdump.pcap':
            return True
        if mime == 'application/octet-stream':
            info = magic.from_file(file).casefold()
            if 'pcap' in info:
                return True
            if 'capture' in info:
                return True
        with open(file, 'rb') as test_file:
            magic_number = test_file.read(4)
        return magic_number in PCAP_MGC
    return False


def parse_args(argv):
    file_list = list()
    for arg in argv:
        if os.path.isdir(arg):
            file_list.extend(entry.path for entry in os.scandir(arg)
                             if entry.is_file() and is_pcap(entry.path))
        elif os.path.isfile(arg) and is_pcap(arg):  # pylint: disable=else-if-used
            file_list.append(arg)
        else:
            warnings.warn(f'invalid path: {arg!r}', UserWarning)
    return file_list


def process(file):
    with tempfile.TemporaryDirectory() as tempdir:
        os.chdir(tempdir)
        os.makedirs('dumps', exist_ok=True)
        print(f'+ Working on PCAP: {file!r}')

        start = time.time()
        try:
            subprocess.check_call(['bro', '--readfile', file,
                                   os.path.join(ROOT, 'scripts')])
        except subprocess.CalledProcessError:
            print(f'+ Failed on PCAP: {file!r}')
        end = time.time()
        print(f'+ Bro processing: {end-start} seconds')
    print(file, file=FILE)


def main_with_args():
    file_list = parse_args(sys.argv[1:])
    if CPU_CNT <= 1:
        [process(file) for file in sorted(file_list)]  # pylint: disable=expression-not-assigned
    else:
        multiprocessing.Pool(CPU_CNT).map(process, sorted(file_list))
    return 0


def main_with_no_args():
    # processed log
    processed_file = list()
    if os.path.isfile(FILE):
        with open(FILE) as file:
            processed_file.extend(line.strip() for line in file)

    # main loop
    while True:
        try:
            file_list = sorted(filter(lambda file: file not in processed_file, parse_args([PCAP_PATH])))
            if file_list:
                if CPU_CNT <= 1:
                    [process(file) for file in file_list]  # pylint: disable=expression-not-assigned
                else:
                    multiprocessing.Pool(CPU_CNT).map(process, file_list)
            time.sleep(INTERVAL)
        except KeyboardInterrupt:
            return 0

        print('+ Starting another turn...')
        processed_file.extend(file_list)


def main():
    if sys.argv[1:]:
        return main_with_args()
    return main_with_no_args()


if __name__ == '__main__':
    sys.exit(main())
