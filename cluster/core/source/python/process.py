# -*- coding: utf-8 -*-
# pylint: disable=import-error, no-name-in-module

import contextlib
import glob
import ipaddress
import json
import os
import pathlib
import re
import shutil
import subprocess
import time
import uuid

import magic

from const import BARE_MODE, DUMP_PATH, FILE, INFO, LOGS_PATH, MIME_MODE, NO_CHKSUM, QUEUE, ROOT
from logparser import parse
from utils import IPAddressJSONEncoder, is_nan, print_file, suppress

# file name regex
FILE_REGEX = re.compile(r'''
    # protocol prefix
    (?P<protocol>DTLS|FTP_DATA|HTTP|IRC_DATA|SMTP|\S+)
    -
    # file UID
    (?P<fuid>F\w+)
    \.
    # media-type
    (?P<media_type>application|audio|example|font|image|message|model|multipart|text|video|\S+)
    \.
    # subtype
    (?P<subtype>\S+)
    \.
    # file extension
    (?P<extension>\S+)
''', re.IGNORECASE | re.VERBOSE)


def rename_dump(local_name, mime_type):
    if MIME_MODE:
        stem, fext = os.path.splitext(local_name)
    else:
        match = FILE_REGEX.match(local_name)
        if match is None:
            return local_name
        stem = f'{match.group("protocol")}-{match.group("fuid")}'
        fext = match.group('extension')
    mime = mime_type.replace('/', '.', 1)

    name = f'{stem}.{mime}{fext}'
    shutil.move(os.path.join(DUMP_PATH, local_name),
                os.path.join(DUMP_PATH, name))
    return name


def generate_log(log_root, log_stem, log_uuid):
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
            with contextlib.suppress(magic.MagicException):
                mime_type = magic.from_file(dump_path, mime=True)
            if MIME_MODE or (mime_type != line.mime_type):
                local_name = rename_dump(local_name, mime_type)
        else:
            dump_path = None

        info = dict(
            timestamp=line.ts if LOG_FILE.format == 'json' else line.ts.timestamp(),
            log_uuid=str(log_uuid),
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


@suppress
def process(file):
    print_file(f'+ Working on PCAP: {file!r}')
    print(f'+ Working on PCAP: {file!r}')

    stem = pathlib.Path(file).stem
    uid = uuid.uuid4()

    env = os.environ
    env['BRO_LOG_SUFFIX'] = f'{uid}.log'

    args = ['bro']
    if BARE_MODE:
        args.append('--bare-mode')
    if NO_CHKSUM:
        args.append('--no-checksums')
    args.extend(['--readfile', file, os.path.join(ROOT, 'scripts')])

    start = time.time()
    try:
        subprocess.check_call(args, env=env)
    except subprocess.CalledProcessError:
        print_file(f'+ Failed on PCAP: {file!r}')
    end = time.time()

    dest_stem = f'{stem}-{uid}'
    dest = os.path.join(LOGS_PATH, dest_stem)
    os.makedirs(dest, exist_ok=True)

    for log in glob.glob(f'*.{uid}.log'):
        with contextlib.suppress(OSError):
            shutil.move(log, os.path.join(dest, log.replace(f'.{uid}.log', '.log')))
    QUEUE.put(dest_stem)
    generate_log(dest, dest_stem, uid)

    print_file(f'+ Bro processing: {end-start} seconds')
    print_file(file, file=FILE)
