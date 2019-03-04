# -*- coding: utf-8 -*-

##############################################################################
import os
import sys

ROOT = os.path.abspath(os.path.dirname(__file__))  # noqa
sys.path.insert(0, ROOT)  # noqa
##############################################################################

import re

import pcapkit


for entry in os.scandir(os.path.join(ROOT, '../contents')):
    with open(entry.path, 'rb') as file:
        report = pcapkit.analyse(file)
        print(entry.name, type(report))

        if isinstance(report, pcapkit.HTTP) and report.info.receipt == 'response':
            filename = re.match(r'''filename="(.*)"''',
                                report.info.header['Content-Disposition'].split(';')[1].strip()).groups()[0]
            with open(os.path.join('extract_files', report.unquote(filename)), 'wb') as file:
                file.write(report.info.raw.body)
