# -*- coding: utf-8 -*-
# pylint: disable=all

import base64
import binascii
import contextlib
import math
import os
import textwrap
import time
import urllib.parse

from const import LOGS_PATH
from logparser import parse
from utils import is_nan, print_file
# from utils import IPAddressJSONEncoder, is_nan, print_file

# today
DATE = time.strftime('%Y-%m-%d')

# log path
LOGS = os.path.join(LOGS_PATH, 'http')
os.makedirs(LOGS, exist_ok=True)

# http log
HTTP_LOG = os.path.join(LOGS_PATH, 'http', f'{DATE}.log')

# macros
SEPARATOR = '\t'
SET_SEPARATOR = ','
EMPTY_FIELD = '(empty)'
UNSET_FIELD = 'NoDef'
FIELDS = ('scrip', 'ad', 'ts', 'url', 'ref', 'ua', 'dstip', 'cookie', 'src_port', 'json', 'method', 'body')
TYPES = ('addr', 'string', 'time', 'string', 'string', 'string', 'addr', 'string', 'port', 'vector[string]', 'string', 'string')


def hexlify(string):
    hex_string = binascii.hexlify(string.encode()).decode()
    return ''.join(map(lambda s: f'\\x{s}', textwrap.wrap(hex_string, 2)))


def init(HTTP_LOG):
    print_file(f'#separator {hexlify(SEPARATOR)}', file=HTTP_LOG)
    print_file(f'#set_separator{SEPARATOR}{SET_SEPARATOR}', file=HTTP_LOG)
    print_file(f'#empty_field{SEPARATOR}{EMPTY_FIELD}', file=HTTP_LOG)
    print_file(f'#unset_field{SEPARATOR}{UNSET_FIELD}', file=HTTP_LOG)
    print_file(f'#path{SEPARATOR}http', file=HTTP_LOG)
    print_file(f'#open{SEPARATOR}{time.strftime("%Y-%m-%d-%H-%M-%S")}', file=HTTP_LOG)
    print_file(f'#fields{SEPARATOR}{SEPARATOR.join(FIELDS)}', file=HTTP_LOG)
    print_file(f'#types{SEPARATOR}{SEPARATOR.join(TYPES)}', file=HTTP_LOG)


def make_url(line):
    host = line.get('host')
    if is_nan(host):
        host = str()
    uri = line.get('uri')
    if is_nan(uri):
        uri = str()
    url = urllib.parse.urljoin(host, uri)

    port = int(line['id.resp_p'])
    if port == 80:
        base = 'http://%s' % line['id.resp_h']
    else:
        base = 'http://%s:%s' % (line['id.resp_h'], line['id.resp_p'])
    return urllib.parse.urljoin(base, url)


def make_b64(data):
    if is_nan(data):
        return None
    return base64.b64encode(data.encode()).decode()


def make_json(line):
    client_headers = line.get('client_header_names')
    if is_nan(client_headers):
        client_headers = list()
    server_headers = line.get('server_header_names')
    if is_nan(server_headers):
        server_headers = list()

    headers = list()
    headers.extend(filter(lambda header: not is_nan(header), client_headers))
    headers.extend(filter(lambda header: not is_nan(header), server_headers))
    return ','.join(filter(lambda header: len(header), headers))


def beautify(obj):
    if obj is None:
        return UNSET_FIELD
    if isinstance(obj, str):
        return obj or EMPTY_FIELD
    if isinstance(obj, (set, list, tuple)):
        return SET_SEPARATOR.join(obj) or EMPTY_FIELD
    return str(obj) or EMPTY_FIELD


def generate(log_name):
    global DATE, HTTP_LOG
    date = time.strftime('%Y-%m-%d')
    if date != DATE:
        close()
        DATE = date

        HTTP_LOG = os.path.join(LOGS_PATH, 'http', f'{DATE}.log')
        init(HTTP_LOG)

    log_root = os.path.join(LOGS_PATH, log_name)
    http_log = os.path.join(log_root, 'http.log')

    if not os.path.isfile(http_log):
        return

    LOG_HTTP = parse(http_log)
    for (index, line) in LOG_HTTP.context.iterrows():
        # record = dict(
        #     srcip=line['id.orig_h'],
        #     ad=None,
        #     ts=math.floor((line['ts'] if LOG_HTTP.format == 'json' else line['ts'].timestamp()) * 1000),
        #     url=make_url(line),
        #     ref=make_b64(line.get('referrer')),
        #     ua=make_ua(line),
        #     dstip=line['id.resp_h'],
        #     cookie=make_cookie(line),
        #     src_port=int(line['id.orig_p']),
        #     # json=make_json(line),
        #     method=line['method'],
        #     body=line['post_body'],
        # )
        record = (
            # scrip
            line['id.orig_h'],
            # ad
            None,
            # ts
            math.floor((line['ts'] if LOG_HTTP.format == 'json' else line['ts'].timestamp()) * 1000),
            # url
            make_url(line),
            # ref
            make_b64(line.get('referrer')),
            # ua
            make_b64(line.get('user_agent')),
            # dstip
            line['id.resp_h'],
            # cookie
            make_b64(line.get('cookies')),
            # src_port
            int(line['id.orig_p']),
            # json
            make_json(line),
            # method
            line.get('method'),
            # body
            make_b64(line.get('post_body')),
        )
        # data = json.dumps(record, cls=IPAddressJSONEncoder)
        data = '\t'.join(map(lambda obj: beautify(obj), record))
        print_file(data, file=HTTP_LOG)


def close():
    print_file(f'#close{SEPARATOR}{time.strftime("%Y-%m-%d-%H-%M-%S")}', file=HTTP_LOG)
