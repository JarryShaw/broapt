# -*- coding: utf-8 -*-

import dataclasses
import multiprocessing
import os
import pathlib
import sys
import time
import typing

# limit on CPU
cpu_count = os.getenv('CORE_CPU')
try:
    CPU_CNT = int(cpu_count)
except (ValueError, TypeError):
    if os.name == 'posix' and 'SC_NPROCESSORS_CONF' in os.sysconf_names:
        CPU_CNT = os.sysconf('SC_NPROCESSORS_CONF')
    elif 'sched_getaffinity' in os.__all__:
        CPU_CNT = len(os.sched_getaffinity(0))  # pylint: disable=E1101
    else:
        CPU_CNT = os.cpu_count() or 1

# Bro config
BOOLEAN_STATES = {'1': True, '0': False,
                  'yes': True, 'no': False,
                  'true': True, 'false': False,
                  'on': True, 'off': False}
DUMP_MIME = BOOLEAN_STATES.get(os.getenv('DUMP_MIME', 'false').strip().lower(), False)
DUMP_PATH = os.getenv('DUMP_PATH', '/dump/').strip()
PCAP_PATH = os.getenv('PCAP_PATH', '/pcap/').strip()

# log files
FILE = os.path.join(PCAP_PATH, 'processed_dump.log')


@dataclasses.dataclass
class Entry:
    path: typing.AnyStr
    name: typing.AnyStr
    mime: typing.AnyStr


def print_file(s, file=FILE):
    with open(file, 'at', 1) as LOG:
        print(s, file=LOG)


def process(entry):
    print_file(entry.path)


def list_dir(path):
    if DUMP_MIME:
        file_list = list()
        for content_type in filter(lambda entry: entry.is_dir(), os.scandir(path)):
            for subtype in filter(lambda entry: entry.is_dir(), os.scandir(content_type.path)):
                mime = '{}/{}'.format(content_type, subtype)
                file_list.extend(Entry(path=entry.path, name=entry.name, mime=mime)
                                 for entry in filter(lambda entry: entry.is_file(), os.scandir(subtype.path)))
    else:
        file_list = list(Entry(path=entry.path, name=entry.name,
                               mime=''.join(pathlib.Path(entry.name).suffixes[:-1])[1:].replace('.', '/', 1))
                         for entry in filter(lambda entry: entry.path != FILE, os.scandir(path)))
    return file_list


def main():
    # processed log
    processed_file = list()
    if os.path.isfile(FILE):
        with open(FILE) as file:
            processed_file.extend(line.strip() for line in file)

    # main loop
    while True:
        try:
            file_list = sorted(filter(lambda entry: entry.path not in processed_file, list_dir(DUMP_PATH)))
            if file_list:
                if CPU_CNT <= 1:
                    [process(entry) for entry in file_list]  # pylint: disable=expression-not-assigned
                else:
                    multiprocessing.Pool(CPU_CNT).map(process, file_list)
            time.sleep(10)
        except KeyboardInterrupt:
            return 0

        print('+ Starting another turn...')
        processed_file.extend(file_list)


if __name__ == '__main__':
    sys.exit(main())
