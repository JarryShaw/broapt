# -*- coding: utf-8 -*-
# pylint: disable=no-member

##############################################################################
import os
import sys

ROOT = os.path.abspath(os.path.dirname(__file__))  # pylint: disable=wrong-import-position
sys.path.insert(0, ROOT)  # pylint: disable=wrong-import-position
##############################################################################

import ipaddress
import mimetypes
import multiprocessing

import magic
import pandas
import pcapkit

from logparser import parse as parse_log

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

# root directory
ROOT = os.path.abspath(os.path.dirname(__file__))

# log information
LOG_HTTP = parse_log(os.path.join(ROOT, '../reass_http.log'))
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


def process(entry):
    with open(entry.path, 'rb') as file:
        report = pcapkit.analyse(file)
    print(entry.name, report.alias)

    if isinstance(report, pcapkit.HTTP) and report.info.receipt == 'response':
        data = report.info.raw.body
        if not data:
            return

        mime = magic.from_buffer(data, mime=True)
        os.makedirs(os.path.join('extract_files', mime), exist_ok=True)

        df = LOG_HTTP.context
        temp = df[df['pkt.path'] == os.path.splitext(entry.name)[0]]['filename'].item()
        filename = temp

        if filename is None:
            ext = mimetypes.guess_extension(mime) or '.dat'
            filename = '%s%s' % (os.path.splitext(entry.name)[0], ext)

        with open(os.path.join('extract_files', mime, report.unquote(filename)), 'wb') as file:
            file.write(data)


def main():
    entries = (pcapkit.corekit.Info(
        path=entry.path,
        name=entry.name,
    ) for entry in os.scandir(os.path.join(ROOT, '../contents')))
    if CPU_CNT > 1:
        multiprocessing.Pool(processes=CPU_CNT).map(process, sorted(entries, key=lambda info: info.name))
    else:
        list(map(process, sorted(entries, key=lambda info: info.name)))


if __name__ == '__main__':
    sys.exit(main())
