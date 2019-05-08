# -*- coding: utf-8 -*-

import ast
import contextlib
import ctypes
import functools
import glob
import ipaddress
import json
import math
import multiprocessing
import os
import pathlib
import re
import shutil
import subprocess
import sys
import traceback
import time
import uuid
import warnings

import magic

from logparser import parse  # pylint: disable=import-error

# repo root path
ROOT = str(pathlib.Path(__file__).parents[1].resolve())

# limit on CPU
try:
    CPU_CNT = int(os.getenv('BROAPT_CORE_CPU'))
except (ValueError, TypeError):
    if os.name == 'posix' and 'SC_NPROCESSORS_CONF' in os.sysconf_names:
        CPU_CNT = os.sysconf('SC_NPROCESSORS_CONF')
    elif 'sched_getaffinity' in os.__all__:
        CPU_CNT = len(os.sched_getaffinity(0))  # pylint: disable=E1101
    else:
        CPU_CNT = os.cpu_count() or 1

# sleep interval
try:
    INTERVAL = int(os.getenv('BROAPT_CORE_INTERVAL'))
except (TypeError, ValueError):
    INTERVAL = 10

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

# PCAP magic numbers
PCAP_MGC = (b'\xa1\xb2\x3c\x4d',
            b'\xa1\xb2\xc3\xd4',
            b'\x4d\x3c\xb2\xa1',
            b'\xd4\xc3\xb2\xa1',
            b'\x0a\x0d\x0d\x0a')

# boolean mapping
BOOLEAN_STATES = {'1': True, '0': False,
                  'yes': True, 'no': False,
                  'true': True, 'false': False,
                  'on': True, 'off': False}

# macros
inited = False
## group by MIME flag
MIME_MODE = None
## extract files path
DUMP_PATH = None
## source PCAP path
PCAP_PATH = os.getenv('BROAPT_PCAP_PATH', '/pcap/')
## log file path
LOGS_PATH = os.getenv('BROAPT_LOGS_PATH', '/var/log/bro/')
## run Bro in bare mode
BARE_MODE = BOOLEAN_STATES.get(os.getenv('BROAPT_BARE_MODE', 'false').casefold(), False)
## run Bro with `-C` option
NO_CHKSUM = BOOLEAN_STATES.get(os.getenv('BROAPT_NO_CHKSUM', 'true').casefold(), True)


def init():
    global inited, DUMP_PATH, MIME_MODE
    inited = True

    # Bro config
    ## log file path
    # LOGS_PATH = os.getenv('LOGS_PATH', '/var/log/bro/')
    ## source PCAP path
    # PCAP_PATH = os.getenv('PCAP_PATH', '/pcap/')
    ## group by MIME flag
    MIME_MODE = BOOLEAN_STATES.get(os.getenv('BROAPT_MIME_MODE', 'true').casefold(), True)
    ## include hash flag
    HASH_MODE = BOOLEAN_STATES.get(os.getenv('BROAPT_HASH_MODE', 'false').casefold(), False)
    ## include X509 flag
    X509_MODE = BOOLEAN_STATES.get(os.getenv('BROAPT_X509_MODE', 'false').casefold(), False)
    ## include entropy flag
    ENTR_MODE = BOOLEAN_STATES.get(os.getenv('BROAPT_ENTROPY_MODE', 'false').casefold(), False)
    ## extract files path
    DUMP_PATH_ENV = os.getenv('BROAPT_DUMP_PATH')
    if DUMP_PATH_ENV is None:
        DUMP_PATH = 'FileExtract::prefix'
    else:
        DUMP_PATH = '"%s"' % DUMP_PATH_ENV.replace('"', '\\"')
    ## buffer size
    try:
        FILE_BUFFER = ctypes.c_uint64(ast.literal_eval(os.getenv('BROAPT_FILE_BUFFER'))).value
    except (SyntaxError, TypeError, ValueError):
        FILE_BUFFER = 'Files::reassembly_buffer_size'
    ## size limit
    try:
        SIZE_LIMIT = ctypes.c_uint64(ast.literal_eval(os.getenv('BROAPT_SIZE_LIMIT'))).value
    except (SyntaxError, TypeError, ValueError):
        SIZE_LIMIT = 'FileExtract::default_limit'
    ## log in JSON format
    JSON_MODE_ENV = os.getenv('BROAPT_JSON_MODE')
    if JSON_MODE_ENV is None:
        JSON_MODE = 'LogAscii::use_json'
    else:
        JSON_MODE_BOOL = BOOLEAN_STATES.get(JSON_MODE_ENV.casefold())
        if JSON_MODE_BOOL is None:
            JSON_MODE = 'LogAscii::use_json'
        else:
            JSON_MODE = 'T' if JSON_MODE_BOOL else 'F'

    # plugin template
    FILE_TEMP = ('@load ../__load__.bro',
                 '',
                 'module FileExtraction;',
                 '',
                 'hook FileExtraction::extract(f: fa_file, meta: fa_metadata) &priority=5 {',
                 '    if ( meta?$mime_type && meta$mime_type == "%s")',
                 '        break;',
                 '}',
                 '')

    # MIME white list
    LOAD_MIME = os.getenv('BROAPT_LOAD_MIME')
    if LOAD_MIME is not None:
        load_file = list()
        for mime_type in filter(len, re.split(r'\s*[,;|]\s*', LOAD_MIME.casefold())):
            safe_mime = re.sub(r'\W', r'-', mime_type, re.ASCII)
            file_name = os.path.join('.', 'plugins', f'extract-{safe_mime}.bro')
            load_file.append(file_name)
            with open(os.path.join(ROOT, 'scripts', file_name), 'w') as zeek_file:
                zeek_file.write(os.linesep.join(FILE_TEMP) % mime_type)
    else:
        load_file = [os.path.join('.', 'plugins', 'extract-all-files.bro')]

    # protocol list
    LOAD_PROTOCOL = os.getenv('BROAPT_LOAD_PROTOCOL')
    if LOAD_PROTOCOL is not None:
        # available protocols
        available_protocols = ('dtls', 'ftp', 'http', 'irc', 'smtp')
        for protocol in filter(lambda protocol: protocol in available_protocols,
                               re.split(r'\s*[,;|]\s*', LOAD_PROTOCOL.casefold())):
            load_file.append(os.path.join('.', 'hooks', f'extract-{protocol}.bro'))

    # prepare regex
    MIME_REGEX = re.compile(r'(?P<prefix>\s*redef mime\s*=\s*)[TF](?P<suffix>\s*;\s*)')
    LOGS_REGEX = re.compile(r'(?P<prefix>\s*redef logs\s*=\s*").*?(?P<suffix>"\s*;\s*)')
    HASH_REGEX = re.compile(r'(?P<prefix>\s*redef hash\s*=\s*)[TF](?P<suffix>\s*;\s*)')
    X509_REGEX = re.compile(r'(?P<prefix>\s*redef x509\s*=\s*)[TF](?P<suffix>\s*;\s*)')
    ENTR_REGEX = re.compile(r'(?P<prefix>\s*redef entropy\s*=\s*)[TF](?P<suffix>\s*;\s*)')
    JSON_REGEX = re.compile(r'(?P<prefix>\s*redef use_json\s*=\s*).*?(?P<suffix>\s*;\s*)')
    SALT_REGEX = re.compile(r'(?P<prefix>\s*redef file_salt\s*=\s*).*?(?P<suffix>\s*;\s*)')
    FILE_REGEX = re.compile(r'(?P<prefix>\s*redef file_buffer\s*=\s*).*?(?P<suffix>\s*;\s*)')  # pylint: disable=redefined-outer-name
    PATH_REGEX = re.compile(r'(?P<prefix>\s*redef path_prefix\s*=\s*).*?(?P<suffix>\s*;\s*)')
    SIZE_REGEX = re.compile(r'(?P<prefix>\s*redef size_limit\s*=\s*).*?(?P<suffix>\s*;\s*)')
    LOAD_REGEX = re.compile(r'^@load\s+.*?\s*')

    # update Bro scripts
    context = list()
    with open(os.path.join(ROOT, 'scripts', 'config.bro')) as config:
        for line in config:
            line = MIME_REGEX.sub(rf'\g<prefix>{"T" if MIME_MODE else "F"}\g<suffix>', line)
            line = LOGS_REGEX.sub(rf'\g<prefix>{os.path.join(LOGS_PATH, "processed_mime.log")}\g<suffix>', line)
            line = HASH_REGEX.sub(rf'\g<prefix>{"T" if HASH_MODE else "F"}\g<suffix>', line)
            line = X509_REGEX.sub(rf'\g<prefix>{"T" if X509_MODE else "F"}\g<suffix>', line)
            line = ENTR_REGEX.sub(rf'\g<prefix>{"T" if ENTR_MODE else "F"}\g<suffix>', line)
            line = JSON_REGEX.sub(rf'\g<prefix>{JSON_MODE}\g<suffix>', line)
            line = SALT_REGEX.sub(rf'\g<prefix>"{uuid.uuid4()}"\g<suffix>', line)
            line = FILE_REGEX.sub(rf'\g<prefix>{FILE_BUFFER}\g<suffix>', line)
            line = PATH_REGEX.sub(rf'\g<prefix>{DUMP_PATH}\g<suffix>', line)
            line = SIZE_REGEX.sub(rf'\g<prefix>{SIZE_LIMIT}\g<suffix>', line)
            if LOAD_REGEX.match(line) is not None:
                break
            context.append(line)
    context.extend(f'@load {file_name}\n' for file_name in load_file)
    with open(os.path.join(ROOT, 'scripts', 'config.bro'), 'w') as config:
        config.writelines(context)

    # get real DUMP_PATH
    if DUMP_PATH_ENV is None:
        try:
            DUMP_PATH_ENV = subprocess.check_output(['bro', '-e', 'print_file(FileExtract::prefix)'],
                                                    stderr=subprocess.DEVNULL, encoding='utf-8').strip()
        except subprocess.CalledProcessError:
            DUMP_PATH_ENV = './extract_files/'
    DUMP_PATH = DUMP_PATH_ENV


# log files
FILE = os.path.join(LOGS_PATH, 'processed_file.log')
TIME = os.path.join(LOGS_PATH, 'processed_time.log')
INFO = os.path.join(LOGS_PATH, 'processed_info.log')


class IPAddressJSONEncoder(json.JSONEncoder):

    def default(self, o):  # pylint: disable=method-hidden
        if isinstance(o, ipaddress._IPAddressBase):  # pylint: disable=protected-access
            return str(o)
        return super().default(o)


def print_file(s, file=TIME):
    with open(file, 'at', 1) as LOG:
        print(s, file=LOG)


def suppress(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            func(*args, **kwargs)
        except Exception:
            traceback.print_exc()
    return wrapper


def is_nan(value):
    if value is None:
        return True
    try:
        return math.isnan(value)
    except TypeError:
        return False


def is_pcap(file):
    with contextlib.suppress(Exception):
        mime = magic.from_file(file, mime=True)
        if mime == 'application/vnd.tcpdump.pcap':
            return True
        if mime == 'application/octet-stream':
            info = magic.from_file(file).casefold()
            if 'pcap' in info:
                return True
            if 'capture' in info:
                return True
        with open(file, 'rb') as test_file:
            magic_number = test_file.read(4)
        return magic_number in PCAP_MGC
    return False


def parse_args(argv):
    file_list = list()
    for arg in argv:
        if os.path.isdir(arg):
            file_list.extend(entry.path for entry in os.scandir(arg)
                             if entry.is_file() and is_pcap(entry.path))
        elif os.path.isfile(arg) and is_pcap(arg):  # pylint: disable=else-if-used
            file_list.append(arg)
        else:
            warnings.warn(f'invalid path: {arg!r}', UserWarning)
    return file_list


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


def generate_log(log_root):
    log_file = os.path.join(log_root, 'files.log')
    if not os.path.isfile(log_file):
        return

    LOG_FILE = parse(log_file)
    LOG_CONN = parse(os.path.join(log_root, 'conn.log'))
    for line in LOG_FILE.context.itertuples():
        if (not hasattr(line, 'extracted')) or is_nan(line.extracted):
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
            dump_path=dump_path,
            local_name=local_name,
            source_name=line.filename if hasattr(line, 'filename') else None,
            hosts=hosts,
            conns=conns,
            bro_mime_type=line.mime_type,
            real_mime_type=mime_type,
        )
        print_file(json.dumps(info, cls=IPAddressJSONEncoder), file=INFO)


@suppress
def process(file):
    if not inited:
        init()
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

    dest = os.path.join(LOGS_PATH, f'{stem}-{uid}')
    os.makedirs(dest, exist_ok=True)

    for log in glob.glob(f'*.{uid}.log'):
        with contextlib.suppress(OSError):
            shutil.move(log, os.path.join(dest, log.replace(f'.{uid}.log', '.log')))
    generate_log(dest)

    print_file(f'+ Bro processing: {end-start} seconds')
    print_file(file, file=FILE)


def main_with_args():
    file_list = parse_args(sys.argv[1:])
    if CPU_CNT <= 1:
        [process(file) for file in sorted(file_list)]  # pylint: disable=expression-not-assigned
    else:
        multiprocessing.Pool(CPU_CNT).map(process, sorted(file_list))
    return 0


def main_with_no_args():
    # processed log
    processed_file = list()
    if os.path.isfile(FILE):
        with open(FILE) as file:
            processed_file.extend(line.strip() for line in file)

    # main loop
    while True:
        try:
            file_list = sorted(filter(lambda file: file not in processed_file, parse_args([PCAP_PATH])))
            if file_list:
                if CPU_CNT <= 1:
                    [process(file) for file in file_list]  # pylint: disable=expression-not-assigned
                else:
                    multiprocessing.Pool(CPU_CNT).map(process, file_list)
            time.sleep(INTERVAL)
        except KeyboardInterrupt:
            return 0

        print_file('+ Starting another turn...')
        print('+ Starting another turn...')
        processed_file.extend(file_list)


def main():
    if sys.argv[1:]:
        return main_with_args()
    return main_with_no_args()


if __name__ == '__main__':
    sys.exit(main())
