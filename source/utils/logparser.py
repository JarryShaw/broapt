# -*- coding: utf-8 -*-

import ast
import collections
import ctypes
import dataclasses
import datetime
import ipaddress
import json
import pprint
import re
import sys
import urllib.parse

import pandas


@dataclasses.dataclass
class TEXTInfo:
    format = 'text'
    path: str
    open: datetime.datetime
    close: datetime.datetime
    context: pandas.DataFrame
    exit_with_error: bool


@dataclasses.dataclass
class JSONInfo:
    format = 'json'
    context: pandas.DataFrame


def parse_text(file, line):
    temp = line.strip().split(' ', maxsplit=1)[1]
    separator = urllib.parse.unquote(temp.replace('\\x', '%'))

    set_separator = file.readline().strip().split(separator)[1]
    def set_parser(s, t): return set(t(e) for e in s.split(set_separator))
    def vector_parser(s, t): return list(t(e) for e in s.split(set_separator))

    empty_field = file.readline().strip().split(separator)[1]
    unset_field = file.readline().strip().split(separator)[1]

    def str_parser(s):
        if s == empty_field:
            return str()
        if s == unset_field:
            return None
        b = ast.literal_eval(f'b{s!r}'.replace('\\\\x', '\\x'))
        return b.decode()

    def port_parser(s):
        if s == unset_field:
            return None
        return ctypes.c_uint16(int(s)).value

    def int_parser(s):
        if s == unset_field:
            return None
        return ctypes.c_int64(int(s)).value

    def count_parser(s):
        if s == unset_field:
            return None
        return ctypes.c_uint64(int(s)).value

    def addr_parser(s):
        if s == unset_field:
            return None
        return ipaddress.ip_address(s)

    def subnet_parser(s):
        if s == unset_field:
            return None
        return ipaddress.ip_network(s)

    def time_parser(s):
        if s == unset_field:
            return None
        return datetime.datetime.fromtimestamp(float(s))

    def float_parser(s):
        if s == unset_field:
            return None
        return float(s)

    def bool_parser(s):
        if s == unset_field:
            return None
        if s == 'T':
            return True
        if s == 'F':
            return False
        raise ValueError

    type_parser = collections.defaultdict(lambda: str_parser, dict(
        string=str_parser,
        port=port_parser,
        enum=str_parser,
        interval=str_parser,
        addr=addr_parser,
        subnet=subnet_parser,
        int=int_parser,
        count=count_parser,
        time=time_parser,
        double=float_parser,
        bool=bool_parser,
    ))

    path = file.readline().strip().split(separator)[1]
    open_time = datetime.datetime.strptime(file.readline().strip().split(separator)[1], '%Y-%m-%d-%H-%M-%S')

    fields = file.readline().strip().split(separator)[1:]
    types = file.readline().strip().split(separator)[1:]
    field_parser = list()
    for (field, type_) in zip(fields, types):
        match_set = re.match(r'set\[(?P<type>.+)\]', type_)
        if match_set is not None:
            set_type = match_set.group('type')
            field_parser.append((field, lambda s: set_parser(
                s, type_parser[set_type])))  # pylint: disable=cell-var-from-loop
            continue

        match_vector = re.match(r'^vector\[(.+?)\]', type_)
        if match_vector is not None:
            vector_type = match_vector.groups()[0]
            field_parser.append((field, lambda s: vector_parser(
                s, type_parser[vector_type])))  # pylint: disable=cell-var-from-loop
            continue

        field_parser.append((field, type_parser[type_]))

    exit_with_error = True
    loglist = list()
    for line in file:  # pylint: disable = redefined-argument-from-local
        if line.startswith('#'):
            exit_with_error = False
            break
        logline = dict()
        for i, s in enumerate(line.strip().split(separator)):
            field_name, field_type = field_parser[i]
            logline[field_name] = field_type(s)
        loglist.append(logline)
    if exit_with_error:
        close_time = datetime.datetime.now()
    else:
        close_time = datetime.datetime.strptime(line.strip().split(separator)[1], '%Y-%m-%d-%H-%M-%S')

    loginfo = TEXTInfo(
        # format='text',
        path=path,
        open=open_time,
        close=close_time,
        context=pandas.DataFrame(loglist),
        exit_with_error=exit_with_error,
    )
    return loginfo


def parse_json(file, line):
    loglist = [json.loads(line)]
    for line in file:  # pylint: disable = redefined-argument-from-local
        loglist.append(json.loads(line))
    loginfo = JSONInfo(
        # format='json',
        context=pandas.DataFrame(loglist),
    )
    return loginfo


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
        pprint.pprint(loginfo)


if __name__ == '__main__':
    sys.exit(main())
