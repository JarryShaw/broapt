# -*- coding: utf-8 -*-
# pylint: disable=import-error, no-name-in-module

import contextlib
import multiprocessing
import os
import sys
import time
import warnings

import magic

from const import CPU_CNT, FILE, INTERVAL, PCAP_PATH
from process import process
from remote import remote
from utils import print_file

try:
    import threading
except ImportError:
    import dummy_threading as threading

# PCAP magic numbers
PCAP_MGC = (b'\xa1\xb2\x3c\x4d',
            b'\xa1\xb2\xc3\xd4',
            b'\x4d\x3c\xb2\xa1',
            b'\xd4\xc3\xb2\xa1',
            b'\x0a\x0d\x0d\x0a')


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

        print_file('+ Starting another turn...')
        print('+ Starting another turn...')
        processed_file.extend(file_list)


def main():
    proxy = multiprocessing.Process(target=remote)
    proxy.start()
    if sys.argv[1:]:
        returncode = main_with_args()
    else:
        returncode = main_with_no_args()
    proxy.close()
    return returncode


if __name__ == '__main__':
    sys.exit(main())
