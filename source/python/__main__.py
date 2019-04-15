# -*- coding: utf-8 -*-
# pylint: disable=no-member

import contextlib
import os
import pathlib
import subprocess
import sys
import time
import warnings

import magic

# repo root path
ROOT = str(pathlib.Path(__file__).parents[1])

# redirect stderr
LOG = open('time.txt', 'wt', 1)


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
        return False
    return False


def parse_args():
    file_list = list()
    for arg in sys.argv[1:]:
        if os.path.isdir(arg):
            file_list.extend(entry.path for entry in os.scandir(arg)
                             if entry.is_file() and is_pcap(entry.path))
        elif os.path.isfile(arg) and is_pcap(arg):
            file_list.append(arg)
        else:
            warnings.warn(f'invalid path: {arg!r}', UserWarning)
    return file_list


def main():
    file_list = parse_args()

    for file in sorted(file_list):
        os.makedirs('dumps', exist_ok=True)
        print(f'+ Working on PCAP: {file!r}', file=LOG)

        start = time.time()
        try:
            subprocess.check_call(['bro', '-r', file,
                                   os.path.join(ROOT, 'scripts')])
        except subprocess.CalledProcessError:
            print(f'+ Failed on PCAP: {file!r}', file=sys.stderr)
        end = time.time()
        print(f'+ Bro processing: {end-start} seconds', file=LOG)

        dest = os.path.join('/test/docker', os.path.split(file)[1])
        os.makedirs(dest, exist_ok=True)

        subprocess.run(f'mv -f *.log {dest}', shell=True)
        subprocess.run(f'mv -f dumps {dest}', shell=True)

    LOG.close()


if __name__ == '__main__':
    sys.exit(main())
