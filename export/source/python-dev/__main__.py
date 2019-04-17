# -*- coding: utf-8 -*-
# pylint: disable=no-member

import builtins
import contextlib
import multiprocessing
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import warnings

import magic

# limit on CPU
cpu_count = os.getenv('CPU')
if cpu_count is None:
    if os.name == 'posix' and 'SC_NPROCESSORS_CONF' in os.sysconf_names:
        CPU_CNT = os.sysconf('SC_NPROCESSORS_CONF')
    elif 'sched_getaffinity' in os.__all__:
        CPU_CNT = len(os.sched_getaffinity(0))  # pylint: disable=E1101
    else:
        CPU_CNT = os.cpu_count() or 1
else:
    CPU_CNT = int(cpu_count)

# repo root path
ROOT = str(pathlib.Path(__file__).parents[1].resolve())

# PCAP magic numbers
PCAP_MGC = (b'\xa1\xb2\x3c\x4d',
            b'\xa1\xb2\xc3\xd4',
            b'\x4d\x3c\xb2\xa1',
            b'\xd4\xc3\xb2\xa1',
            b'\x0a\x0d\x0d\x0a')

# log files
FILE = '/pcap/processed_file.log'
TIME = '/pcap/processed_time.log'


def print(s, file=TIME):  # pylint: disable=redefined-builtin
    with open(file, 'at', 1) as LOG:
        builtins.print(s, file=LOG)
    builtins.print(s, file=sys.stderr)


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
        elif os.path.isfile(arg) and is_pcap(arg):
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
    print(file, FILE)


def main_with_args():
    file_list = parse_args(sys.argv[1:])
    if CPU_CNT <= 1:
        [process(file) for file in sorted(file_list)]  # pylint: disable=expression-not-assigned
    else:
        multiprocessing.Pool(CPU_CNT).map(process, sorted(file_list))
    return 0


def main_without_args():
    # processed log
    processed_file = list()
    if os.path.isfile(FILE):
        with open(FILE) as file:
            processed_file.extend(line.strip() for line in file)

    # main loop
    while True:
        try:
            file_list = sorted(filter(lambda file: file not in processed_file, parse_args(['/pcap'])))
            if file_list:
                if CPU_CNT <= 1:
                    [process(file) for file in file_list]  # pylint: disable=expression-not-assigned
                else:
                    multiprocessing.Pool(CPU_CNT).map(process, file_list)
            time.sleep(10)
        except KeyboardInterrupt:
            return 0
        print('+ Starting another turn...')


def main():
    if sys.argv[1:]:
        return main_with_args()
    return main_without_args()


if __name__ == '__main__':
    sys.exit(main())
