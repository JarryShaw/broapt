# -*- coding: utf-8 -*-

##############################################################################
import os
import sys

ROOT = os.path.abspath(os.path.dirname(__file__))  # noqa
sys.path.insert(0, ROOT)  # noqa
##############################################################################

import mimetypes
import multiprocessing
import re

import magic
import pcapkit


def process(entry):
    with open(entry.path, 'rb') as file:
        report = pcapkit.analyse(file)
    print(entry.name, report.alias)

    if isinstance(report, pcapkit.HTTP) and report.info.receipt == 'response':
        data = report.info.raw.body
        if not data:
            return report

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
    return report


def multi_processing():
    entries = (pcapkit.corekit.Info(
        path=entry.path,
        name=entry.name,
    ) for entry in os.scandir(os.path.join(ROOT, '../contents')))
    multiprocessing.Pool().map(process, entries)


def mono_processing():
    for entry in os.scandir(os.path.join(ROOT, '../contents')):
        process(entry)


if __name__ == '__main__':
    multi_processing()
