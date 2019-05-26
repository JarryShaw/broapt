# -*- coding: utf-8 -*-

import ast
import ctypes
import os
import pathlib
import re
import subprocess

# repo root path
ROOT = str(pathlib.Path(__file__).parents[1].resolve())

# boolean mapping
BOOLEAN_STATES = {'1': True, '0': False,
                  'yes': True, 'no': False,
                  'true': True, 'false': False,
                  'on': True, 'off': False}

# Bro config
## log file path
LOGS_PATH = os.getenv('LOGS_PATH', '/var/log/bro/')
## source PCAP path
PCAP_PATH = os.getenv('PCAP_PATH', '/pcap/')
## group by MIME flag
MIME_MODE = BOOLEAN_STATES.get(os.getenv('BROAPT_MIME_MODE', 'true').casefold(), True)
## include hash flag
HASH_MODE_MD5 = BOOLEAN_STATES.get(os.getenv('BROAPT_HASH_MD5', 'false').casefold(), False)
HASH_MODE_SHA1 = BOOLEAN_STATES.get(os.getenv('BROAPT_HASH_SHA1', 'false').casefold(), False)
HASH_MODE_SHA256 = BOOLEAN_STATES.get(os.getenv('BROAPT_HASH_SHA256', 'false').casefold(), False)
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
HASH_REGEX_MD5 = re.compile(r'(?P<prefix>\s*redef md5\s*=\s*)[TF](?P<suffix>\s*;\s*)')
HASH_REGEX_SHA1 = re.compile(r'(?P<prefix>\s*redef sha1\s*=\s*)[TF](?P<suffix>\s*;\s*)')
HASH_REGEX_SHA256 = re.compile(r'(?P<prefix>\s*redef sha256\s*=\s*)[TF](?P<suffix>\s*;\s*)')
X509_REGEX = re.compile(r'(?P<prefix>\s*redef x509\s*=\s*)[TF](?P<suffix>\s*;\s*)')
ENTR_REGEX = re.compile(r'(?P<prefix>\s*redef entropy\s*=\s*)[TF](?P<suffix>\s*;\s*)')
JSON_REGEX = re.compile(r'(?P<prefix>\s*redef use_json\s*=\s*).*?(?P<suffix>\s*;\s*)')
SALT_REGEX = re.compile(r'(?P<prefix>\s*redef file_salt\s*=\s*).*?(?P<suffix>\s*;\s*)')
FILE_REGEX = re.compile(
    r'(?P<prefix>\s*redef file_buffer\s*=\s*).*?(?P<suffix>\s*;\s*)')  # pylint: disable=redefined-outer-name
PATH_REGEX = re.compile(r'(?P<prefix>\s*redef path_prefix\s*=\s*).*?(?P<suffix>\s*;\s*)')
SIZE_REGEX = re.compile(r'(?P<prefix>\s*redef size_limit\s*=\s*).*?(?P<suffix>\s*;\s*)')
LOAD_REGEX = re.compile(r'^@load\s+.*?\s*')

# update Bro scripts
context = list()
with open(os.path.join(ROOT, 'scripts', 'config.bro')) as config:
    for line in config:
        line = MIME_REGEX.sub(rf'\g<prefix>{"T" if MIME_MODE else "F"}\g<suffix>', line)
        line = LOGS_REGEX.sub(rf'\g<prefix>{os.path.join(LOGS_PATH, "mime.log")}\g<suffix>', line)
        line = HASH_REGEX_MD5.sub(rf'\g<prefix>{"T" if HASH_MODE_MD5 else "F"}\g<suffix>', line)
        line = HASH_REGEX_SHA1.sub(rf'\g<prefix>{"T" if HASH_MODE_SHA1 else "F"}\g<suffix>', line)
        line = HASH_REGEX_SHA256.sub(rf'\g<prefix>{"T" if HASH_MODE_SHA256 else "F"}\g<suffix>', line)
        line = X509_REGEX.sub(rf'\g<prefix>{"T" if X509_MODE else "F"}\g<suffix>', line)
        line = ENTR_REGEX.sub(rf'\g<prefix>{"T" if ENTR_MODE else "F"}\g<suffix>', line)
        line = JSON_REGEX.sub(rf'\g<prefix>{JSON_MODE}\g<suffix>', line)
        line = FILE_REGEX.sub(rf'\g<prefix>{FILE_BUFFER}\g<suffix>', line)
        line = PATH_REGEX.sub(rf'\g<prefix>{DUMP_PATH}\g<suffix>', line)
        line = SIZE_REGEX.sub(rf'\g<prefix>{SIZE_LIMIT}\g<suffix>', line)
        if LOAD_REGEX.match(line) is not None:
            if os.path.isdir(os.path.join(ROOT, 'scripts', 'sites')):
                load_file.append(os.path.join('.', 'sites'))
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


def file_salt(uid):
    with open(os.path.join(ROOT, 'scripts', 'config.bro')) as config:  # pylint: disable=redefined-outer-name
        context = [SALT_REGEX.sub(rf'\g<prefix>"{uid}"\g<suffix>', line) for line in config]  # pylint: disable=redefined-outer-name
    with open(os.path.join(ROOT, 'scripts', 'config.bro'), 'w') as config:
        config.writelines(context)
