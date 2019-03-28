# -*- coding: utf-8 -*-

import ast
import json
import re
import time
import sys

import pandas
import pcapkit


def parse_text(file, line):
    separator = ast.literal_eval(f'{line.strip().split(" ")[1]}')
    set_separator = file.readline().strip().split(separator)[1]
    empty_field = file.readline().strip().split(separator)[1]
    unset_field = file.readline().strip().split(separator)[1]
    path = file.readline().strip().split(separator)[1]
    open_ = time.strptime(file.readline().strip().split(separator)[1],
                          '%Y-%m-%d-%H-%M-%S')
    fields = file.readline().strip().split(separator)[1:]
    types = file.readline().strip().split(separator)[1:]


def parse_json(file, line):
    loglist = [json.loads(line)]
    for line in file:
        loglist.append(json.loads(line))
    loginfo = pcapkit.corekit.Info(
        format='json',
        context=pandas.DataFrame(loglist),
    )
    return loglist


def parse(filename):
    with open(filename) as file:
        line = file.readline()
        if line.startswith('#'):
            loginfo = parse_text(file, line)
        else:
            loginfo = parse_json(file, line)
    return loginfo

def main():
    for logfile in sys.argv[1:]:
        loginfo = parse(logfile)
        print(loginfo)


if __name__ == '__main__':
    sys.exit(main())
