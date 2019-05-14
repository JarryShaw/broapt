# -*- coding: utf-8 -*-
# pylint: disable=all

import base64
import json
import math
import os
import urllib.parse

from const import LOGS_PATH
from logparse import parse, str_parser
from utils import is_nan, print_file

HTTP_LOG = os.path.join(LOGS_PATH, 'http.log')


def make_url(line):
    host = line.get('host')
    if is_nan(host):
        host = str()
    uri = line.get('uri')
    if is_nan(uri):
        uri = str()
    return urllib.parse.urljoin(host, uri)


def make_ref(line):
    referrer = line.get('referrer')
    if is_nan(referrer):
        return None
    return base64.b64encode(referrer.encode()).decode()


def make_ua(line):
    user_agent = line.get('user_agent')
    if is_nan(user_agent):
        return None
    return base64.b64encode(user_agent.encode()).decode()


def make_cookie(line):
    cookies = line.get('cookie')
    if is_nan(cookies):
        return None
    return base64.b64encode(cookies.encode()).decode()


def make_json(line):
    headers = line.get('headers')
    if is_nan(headers):
        return None
    return base64.b64encode(headers.encode()).decode()


def generate(log_name):
    log_root = os.path.join(LOGS_PATH, log_name)
    http_log = os.path.join(log_root, 'http.log')

    if not os.path.isfile(http_log):
        return

    hook = dict(
        header_rec=str_parser
    )

    LOG_HTTP = parse(http_log, hook=hook)
    for (index, line) in LOG_HTTP.context.iterrows():
        record = dict(
            srcip=line['id.orig_h'],
            ad=None,
            ts=(line['ts'] if LOG_HTTP.format == 'json' else line['ts'].timestamp()) * 1000,
            url=make_url(line) or None,
            ref=make_ref(line),
            ua=make_ua(line),
            dstip=line['id.resp_h'],
            cookie=make_cookie(line),
            src_port=int(line['id.orig_p']),
            json=make_json(line),
        )
        print_file(json.dumps(record), file=HTTP_LOG)
