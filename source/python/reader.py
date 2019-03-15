# -*- coding: utf-8 -*-

##############################################################################
import os
import sys

ROOT = os.path.abspath(os.path.dirname(__file__))  # noqa
sys.path.insert(0, ROOT)  # noqa
##############################################################################

import ipaddress
import json
import mimetypes
import multiprocessing
import re

import magic
import pcapkit

# limit on CPU
if os.name == 'posix' and 'SC_NPROCESSORS_CONF' in os.sysconf_names:
    CPU_CNT = os.sysconf('SC_NPROCESSORS_CONF')
elif 'sched_getaffinity' in os.__all__:
    CPU_CNT = len(os.sched_getaffinity(0))  # pylint: disable=E1101
else:
    CPU_CNT = os.cpu_count() or 1


def process(entry):
    def parse(string):
        addr, port = string.rsplit(':', maxsplit=1)
        ip = ipaddress.ip_address(re.sub(r'[\[\]]', r'', addr))
        port = int(port)
        return ip, port

    uid, address, direction = os.path.splitext(entry.name)[0].split('_')
    src, dst = address.split('-')
    src_ip, src_port = parse(src)
    dst_ip, dst_port = parse(dst)

    reassembly = pcapkit.reassemble(pcapkit.TCP)
    with open(entry.path) as file:
        for (index, line) in enumerate(file):
            data = json.loads(line)
            byte = bytes.fromhex(data['payload'])

            fragment = dict(
                bufid=(src_ip,
                       dst_ip,
                       src_port,
                       dst_port),
                num=index,
                ack=data['ack'],
                dsn=data['dsn'],
                syn=data['syn'],
                fin=data['fin'],
                rst=data['rst'],
                payload=bytearray(byte),
                first=data['first'],
                last=data['last'],
                len=data['len'],
            )
            reassembly(fragment)

    for packet in reassembly.datagram:
        for report in packet.packets:
            print(entry.name, report.alias)

            if isinstance(report, pcapkit.HTTP) and report.info.receipt == 'response':
                data = report.info.raw.body
                if not data:
                    return

                content_disposition = report.info.header.get('Content-Disposition')
                mime = magic.from_buffer(data, mime=True)
                os.makedirs(os.path.join('extract_files', mime), exist_ok=True)

                if content_disposition is None:
                    ext = mimetypes.guess_extension(mime) or '.dat'
                    filename = '%s%s' % (os.path.splitext(entry.name)[0], ext)
                else:
                    try:
                        filename = re.match(r'''filename="(.*)"''',
                                            content_disposition.split(';')[1].strip()).groups()[0]
                    except Exception:
                        ext = mimetypes.guess_extension(mime) or '.dat'
                        filename = '%s%s' % (os.path.splitext(entry.name)[0], ext)

                with open(os.path.join('extract_files', mime, report.unquote(filename)), 'wb') as file:
                    file.write(data)


def multi_processing():
    entries = (pcapkit.corekit.Info(
        path=entry.path,
        name=entry.name,
    ) for entry in os.scandir(os.path.join(ROOT, '../logs')))
    multiprocessing.Pool(processes=CPU_CNT).map(process, entries)


def mono_processing():
    for entry in os.scandir(os.path.join(ROOT, '../logs')):
        process(entry)


if __name__ == '__main__':
    multi_processing()
