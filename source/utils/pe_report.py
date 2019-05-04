# -*- coding: utf-8 -*-

import collections
import json
import sys

import pandas

Info = collections.namedtuple('Info', ['name', 'error', 'corrupt'])


def parse(filename):
    DATA = []
    with open(filename) as file:
        report = json.load(file)
    for pe, info in report.items():
        warnings = info.get('Parsing Warnings')
        if warnings is None:
            DATA.append(Info(name=pe, error=False, corrupt=False))
            continue
        error = corrupt = False
        for line in map(lambda s: s.casefold(), warnings):
            if 'error' in line:
                error = True
            if 'corrupt' in line:
                corrupt = True
        DATA.append(Info(name=pe, error=error, corrupt=corrupt))
    return pandas.DataFrame(DATA)


if __name__ == '__main__':
    sys.exit(parse(sys.argv[1]))
