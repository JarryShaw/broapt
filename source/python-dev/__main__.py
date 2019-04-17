# -*- coding: utf-8 -*-
# pylint: disable=no-member

import concurrent.futures
import contextlib
import json
import multiprocessing
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import warnings

import magic
import requests_futures

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
ROOT = str(pathlib.Path(__file__).parents[1])

# redirect stderr
LOG = open('time.txt', 'wt', 1)

# VT API URL
URL = 'https://www.virustotal.com/vtapi/v2/file/scan'
API = os.getenv('VT_API')
if API is None:
    raise KeyError('[VT_API] VirusTotal API key not set')
PARAMS = dict(apikey=API)


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


def process(file):
    with tempfile.TemporaryDirectory() as tempdir:
        os.chdir(tempdir)
        os.makedirs('dumps', exist_ok=True)
        print(f'+ Working on PCAP: {file!r}', file=LOG)

        start = time.time()
        try:
            subprocess.check_call(['bro', '--readfile', file,
                                   os.path.join(ROOT, 'scripts')])
        except subprocess.CalledProcessError:
            print(f'+ Failed on PCAP: {file!r}', file=LOG)
        end = time.time()
        print(f'+ Bro processing: {end-start} seconds', file=LOG)

        dest = os.path.join('/test/docker', os.path.split(file)[1])
        os.makedirs(dest, exist_ok=True)

        pe_path = os.path.join('dumps', 'application/x-dosexec')
        if os.path.isdir(pe_path):
            pe_list = sorted(entry.path for entry in os.scandir(pe_path))
            session = requests_futures.sessions.FuturesSession(executor=concurrent.futures.ThreadPoolExecutor(max_workers=CPU_CNT))  # pylint: disable=line-too-long

            request_list = list()
            for path in pe_list:
                with open(path, 'rb') as pe:
                    FILES = dict(file=(path, pe))
                    request_list.append((path, session.post(URL, files=FILES, params=PARAMS)))

            response_dict = dict()
            for path, request in request_list:
                response = request.result()
                response_dict[path] = response.json()

            with open(os.path.join(dest, 'vt.json'), 'w') as json_file:
                json.dump(response_dict, json_file)
        else:
            warnings.warn(f'no pe extracted from {file!r}', UserWarning)

        subprocess.run(f'mv -f *.log {dest}', shell=True)
        subprocess.run(f'mv -f dumps {dest}', shell=True)


def main():
    file_list = parse_args()
    if CPU_CNT < 1:
        [process(file) for file in sorted(file_list)]  # pylint: disable=expression-not-assigned
    else:
        multiprocessing.Pool(CPU_CNT).map(process, sorted(file_list))
    LOG.close()


if __name__ == '__main__':
    sys.exit(main())
