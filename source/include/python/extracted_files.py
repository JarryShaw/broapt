# -*- coding: utf-8 -*-
# pylint: disable=all

import contextlib
import ipaddress
import json
import os
import re
import tarfile
import time

import magic

from const import DUMP_PATH, LOGS_PATH
from logparser import parse
from utils import is_nan, print_file

# today
DATE = time.strftime('%Y-%m-%d')

# log path
LOGS = os.path.join(LOGS_PATH, 'info')
os.makedirs(LOGS, exist_ok=True)


class IPAddressJSONEncoder(json.JSONEncoder):

    def default(self, o):  # pylint: disable=method-hidden
        if isinstance(o, ipaddress._IPAddressBase):  # pylint: disable=protected-access
            return str(o)
        return super().default(o)


# def rename_dump(local_name, mime_type):
#     if MIME_MODE:
#         stem, fext = os.path.splitext(local_name)
#     else:
#         match = FILE_REGEX.match(local_name)
#         if match is None:
#             return local_name
#         stem = f'{match.group("protocol")}-{match.group("fuid")}.{match.group("pcap")}'
#         fext = match.group('extension')
#     mime = mime_type.replace('/', '.', 1)

#     name = f'{stem}.{mime}{fext}'
#     shutil.move(os.path.join(DUMP_PATH, local_name),
#                 os.path.join(DUMP_PATH, name))
#     return name


def archive(date):
    log_info = os.path.join(LOGS_PATH, 'info', f'{date}.log')

    extracted_files = list()
    with open(log_info) as file:
        for line in filter(lambda line: line.strip(), file):
            info = json.loads(line.strip())
            if info['dump_path'] is None:
                continue
            extracted_files.append((info['dump_path'], info['local_name']))

    tar_path = os.path.join(DUMP_PATH, f'{date}.tar.gz')
    with tarfile.open(tar_path, 'w:gz') as tar_file:
        for args in extracted_files:
            tar_file.add(*args)
            os.remove(args[0])


def generate_log(log_name):
    global DATE
    date = time.strftime('%Y-%m-%d')
    if date != DATE:
        archive(DATE)
        DATE = date
    INFO = os.path.join(LOGS_PATH, 'info', f'{DATE}.log')

    log_stem = log_name
    log_root = os.path.join(LOGS_PATH, log_name)
    log_uuid = re.match(r'.*?-(?P<uuid>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', log_stem, re.IGNORECASE).group('uuid')

    log_file = os.path.join(log_root, 'files.log')
    if not os.path.isfile(log_file):
        return

    LOG_FILE = parse(log_file)
    LOG_CONN = parse(os.path.join(log_root, 'conn.log'))
    for line in LOG_FILE.context.itertuples():
        if is_nan(getattr(line, 'extracted', None)):
            continue
        hosts = [dict(tx=ipaddress.ip_address(tx),
                      rx=ipaddress.ip_address(rx))
                 for (tx, rx) in zip(line.tx_hosts, line.rx_hosts)]

        conns = list()
        is_orig = line.is_orig
        for conn_uid in line.conn_uids:
            record = next(LOG_CONN.context[lambda df: df.uid == conn_uid].iterrows())[1]  # pylint: disable=cell-var-from-loop
            if is_orig:
                conn = dict(
                    src_h=ipaddress.ip_address(record['id.orig_h']),
                    src_p=int(record['id.orig_p']),
                    dst_h=ipaddress.ip_address(record['id.resp_h']),
                    dst_p=int(record['id.resp_p']),
                )
            else:
                conn = dict(
                    src_h=ipaddress.ip_address(record['id.resp_h']),
                    src_p=int(record['id.resp_p']),
                    dst_h=ipaddress.ip_address(record['id.orig_h']),
                    dst_p=int(record['id.orig_p']),
                )
            conns.append(conn)

        local_name = line.extracted
        mime_type = None
        dump_path = os.path.join(DUMP_PATH, local_name)
        if os.path.exists(dump_path):
            with contextlib.suppress(Exception):
                mime_type = magic.detect_from_filename(dump_path).mime_type
            # if mime_type is None or MIME_REGEX.match(mime_type) is None:
            #     if MIME_MODE:
            #         local_name = rename_dump(local_name, line.mime_type)
            # else:
            #     if MIME_MODE or (mime_type != line.mime_type):  # pylint: disable=else-if-used
            #         local_name = rename_dump(local_name, mime_type)
        else:
            dump_path = None

        info = dict(
            timestamp=line.ts if LOG_FILE.format == 'json' else line.ts.timestamp(),
            log_uuid=log_uuid,
            log_path=log_root,
            log_name=log_stem,
            dump_path=dump_path,
            local_name=local_name,
            source_name=getattr(line, 'filename', None),
            hosts=hosts,
            conns=conns,
            bro_mime_type=line.mime_type,
            real_mime_type=mime_type,
            hash=dict(
                md5=getattr(line, 'md5', None),
                sha1=getattr(line, 'sha1', None),
                sha256=getattr(line, 'sha256', None),
            )
        )
        print_file(json.dumps(info, cls=IPAddressJSONEncoder), file=INFO)
