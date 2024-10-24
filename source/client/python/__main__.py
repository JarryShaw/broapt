# -*- coding: utf-8 -*-
# pylint: disable=import-error, no-name-in-module

import contextlib
import multiprocessing
import os
import sys
import time
import warnings

import magic

from const import CPU_CNT, FILE, INTERVAL, PCAP_PATH, TIME
from process import process
from remote import remote_proc
from utils import print_file

# PCAP magic numbers
PCAP_MGC = (b'\xa1\xb2\x3c\x4d',
            b'\xa1\xb2\xc3\xd4',
            b'\x4d\x3c\xb2\xa1',
            b'\xd4\xc3\xb2\xa1',
            b'\x0a\x0d\x0d\x0a')


def is_pcap(file):
    with contextlib.suppress(Exception):
        report = magic.detect_from_filename(file)
        if report.mime_type == 'application/vnd.tcpdump.pcap':
            return True
        if report.mime_type == 'application/octet-stream':
            info = report.name.casefold()
            if 'pcap' in info:
                return True
            if 'capture' in info:
                return True
        with open(file, 'rb') as test_file:
            magic_number = test_file.read(4)
        return magic_number in PCAP_MGC
    return False


def listdir(path):
    file_list = list()
    for entry in os.scandir(path):
        if entry.is_dir():
            file_list.extend(listdir(entry.path))
        else:
            file_list.append(entry.path)
    return file_list


def parse_args(argv):
    file_list = list()
    for arg in argv:
        if os.path.isdir(arg):
            file_list.extend(filter(is_pcap, listdir(arg)))
        elif os.path.isfile(arg) and is_pcap(arg):  # pylint: disable=else-if-used
            file_list.append(arg)
        else:
            warnings.warn(f'invalid path: {arg!r}', UserWarning)
    return file_list


def check_history():
    processed_file = list()
    if os.path.isfile(FILE):
        with open(FILE) as file:
            processed_file.extend(line.strip() for line in file)
    return processed_file


def main_with_args():
    file_list = parse_args(sys.argv[1:])
    if CPU_CNT <= 1:
        [process(file) for file in sorted(file_list)]  # pylint: disable=expression-not-assigned
    else:
        multiprocessing.Pool(CPU_CNT).map(process, sorted(file_list))
    return 0


def main_with_no_args():
    # main loop
    while True:
        try:
            processed_file = set(check_history())
            pcap_file = set(parse_args([PCAP_PATH]))
            file_list = sorted(pcap_file - processed_file)
            del processed_file

            if file_list:
                if CPU_CNT <= 1:
                    [process(file) for file in file_list]  # pylint: disable=expression-not-assigned
                else:
                    multiprocessing.Pool(CPU_CNT).map(process, file_list)
            time.sleep(INTERVAL)
        except KeyboardInterrupt:
            return 0

        print_file('+ Starting another turn...', file=TIME)
        print('+ Starting another turn...')


def main():
    with remote_proc():
        if sys.argv[1:]:
            return main_with_args()
        return main_with_no_args()


if __name__ == '__main__':
    sys.exit(main())
