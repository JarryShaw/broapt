# -*- coding: utf-8 -*-
# pylint: disable=no-member

import ipaddress
import mimetypes
import multiprocessing
import os
import pathlib
import subprocess
import sys
import time
import warnings

import magic
import pandas
import pcapkit

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from logparser import parse as parse_log  # pylint disable=wrong-import-position

# repo root path
ROOT = str(pathlib.Path(__file__).parents[1])

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

# HTTP log
LOG_HTTP = None

# redirect stderr
LOG = open('reass_time.txt', 'wt', 1)


def update_log():
    global LOG_HTTP
    LOG_HTTP = parse_log('reass_http.log')

    if LOG_HTTP.format == 'json':
        def format_path(series):
            uid = series[0]
            is_orig = series[1]
            orig_h = ipaddress.ip_address(series[2])
            orig_p = series[3]
            resp_h = ipaddress.ip_address(series[4])
            resp_p = series[5]
            ack = series[6]

            if not is_orig:
                orig_h, resp_h = resp_h, orig_h
                orig_p, resp_p = resp_p, orig_p

            if orig_h.version == 6:
                orig_h = f'[{orig_h}]'
            if resp_h.version == 6:
                resp_h = f'[{resp_h}]'

            return f'{uid}_{orig_h}:{orig_p}-{resp_h}:{resp_p}_{ack}'
    else:
        def format_path(series):
            uid, is_orig, orig_h, orig_p, resp_h, resp_p, ack = series

            if not is_orig:
                orig_h, resp_h = resp_h, orig_h
                orig_p, resp_p = resp_p, orig_p

            if orig_h.version == 6:
                orig_h = f'[{orig_h}]'
            if resp_h.version == 6:
                resp_h = f'[{resp_h}]'

            return f'{uid}_{orig_h}:{orig_p}-{resp_h}:{resp_p}_{ack}'

    path_dict = {index: format_path(series) for (index, series) in LOG_HTTP.context[
        ['pkt.uid', 'pkt.is_orig',
         'pkt.id.orig_h', 'pkt.id.orig_p',
         'pkt.id.resp_h', 'pkt.id.resp_p',
         'pkt.ack']
    ].iterrows()}
    LOG_HTTP.context['pkt.path'] = pandas.Series(path_dict)


def process_contents(entry):
    with open(entry.path, 'rb') as file:
        report = pcapkit.analyse(file)
    # print(entry.name, report.alias)

    if isinstance(report, pcapkit.HTTP) and report.info.receipt == 'response':
        data = report.info.raw.body
        if not data:
            return

        mime = magic.from_buffer(data, mime=True)
        os.makedirs(os.path.join('extract_files', mime), exist_ok=True)

        try:
            df = LOG_HTTP.context
            filename = df[df['pkt.path'] == os.path.splitext(entry.name)[0]]['filename'].item()
        except ValueError:
            filename = None

        info = magic.from_buffer(data)
        with open('extract_files.log', 'a') as file:
            file.write(f'{entry.name}\t{filename or "-"}\t{mime}\t{info}{os.linesep}')

        if filename is None:
            if mime == 'application/octet-stream':
                ext = '.dat'
            else:
                ext = mimetypes.guess_extension(mime, strict=False) or '.dat'
            filename = f'{os.path.splitext(entry.name)[0]}{ext}'

        dest = report.unquote(filename).replace(os.path.sep, ':')
        with open(os.path.join('extract_files', mime, dest), 'wb') as file:
            file.write(data)


def process_logs(entry):
    log_suffix = os.getenv('BRO_LOG_SUFFIX', '.log')
    basename, suffix = os.path.splitext(entry.name)
    if suffix != log_suffix:
        return

    dest = os.path.join('contents', basename)
    try:
        subprocess.check_call([os.path.join(ROOT, 'build/reass'), entry.path, dest])
    except subprocess.CalledProcessError:
        print(entry.name, file=sys.stderr)


def main():
    file_list = list()
    for arg in sys.argv[1:]:
        if os.path.isdir(arg):
            file_list.extend(entry.path for entry in os.scandir(arg)
                             if entry.is_file() and ('pcap' in magic.from_file(entry.path)))
        elif os.path.isfile(arg) and ('pcap' in magic.from_file(arg)):
            file_list.append(arg)
        else:
            warnings.warn(f'invalid path: {arg!r}', UserWarning)

    with open('extract_files.log', 'w') as file:
        file.write(f'#separator \\x09{os.linesep}')
        file.write(f'#set_separator\x09,{os.linesep}')
        file.write(f'#empty_field\x09(empty){os.linesep}')
        file.write(f'#unset_field\x09-{os.linesep}')
        file.write(f'#path\x09extract_files{os.linesep}')
        file.write(f'#open\x09{time.strftime("%Y-%m-%d-%H-%M-%S")}{os.linesep}')

    for file in sorted(file_list):
        print(f'Working on PCAP: {file!r}', file=LOG)

        start = time.time()
        try:
            subprocess.check_call(['bro', '-br', file, os.path.join(ROOT, 'scripts/hooks/http.bro')])
        except subprocess.CalledProcessError:
            print(f'Failed on PCAP: {file!r}', file=sys.stderr)
        end = time.time()
        print(f'Bro processing: {end-start} seconds', file=LOG)

        entries = (pcapkit.corekit.Info(
            path=entry.path,
            name=entry.name,
        ) for entry in os.scandir('logs') if entry.is_file())
        start = time.time()
        if CPU_CNT > 1:
            multiprocessing.Pool(processes=CPU_CNT).map(process_logs, sorted(entries, key=lambda info: info.name))
        else:
            list(map(process_logs, sorted(entries, key=lambda info: info.name)))
        end = time.time()
        print(f'C/C++ reassembling: {end-start} seconds', file=LOG)

        update_log()
        entries = (pcapkit.corekit.Info(
            path=entry.path,
            name=entry.name,
        ) for entry in os.scandir('contents') if entry.is_file())
        start = time.time()
        if CPU_CNT > 1:
            multiprocessing.Pool(processes=CPU_CNT).map(process_contents, sorted(entries, key=lambda info: info.name))
        else:
            list(map(process_contents, sorted(entries, key=lambda info: info.name)))
        end = time.time()
        print(f'Python analysing: {end-start} seconds', file=LOG)

        subprocess.run(['mv', '-f', 'reass_http.log', f'/test/reass_http-{os.path.split(file)[1]}.log'])
        subprocess.run(['mv', '-f', 'contents', f'/test/contents-{os.path.split(file)[1]}'])
        subprocess.run(['mv', '-f', 'logs', f'/test/logs-{os.path.split(file)[1]}'])
        subprocess.run(['rm', '-rf', 'reass_http.log', 'contents', 'logs'])
        os.makedirs('contents', exist_ok=True)
        os.makedirs('logs', exist_ok=True)

    with open('extract_files.log', 'a') as file:
        file.write(f'#close\x09{time.strftime("%Y-%m-%d-%H-%M-%S")}{os.linesep}')
    LOG.close()


if __name__ == '__main__':
    sys.exit(main())
