# -*- coding: utf-8 -*-

import ast
import ctypes
import os
import pathlib
import re
import uuid

# repo root path
ROOT = str(os.path.join(pathlib.Path(__file__).parents[1].resolve(), 'bro', 'source'))

# Bro config
## group by MIME flag
BOOLEAN_STATES = {'1': True, '0': False,
                  'yes': True, 'no': False,
                  'true': True, 'false': False,
                  'on': True, 'off': False}
DUMP_MIME = BOOLEAN_STATES.get(os.getenv('DUMP_MIME', 'true').strip().lower(), True)
## log file path
LOGS_PATH = os.getenv('LOGS_PATH', '/var/log/bro/').strip()
## extract files path
DUMP_PATH = os.getenv('DUMP_PATH')
if DUMP_PATH is None:
    DUMP_PATH = 'FileExtract::prefix'
else:
    DUMP_PATH = '"%s"' % DUMP_PATH.replace('"', '\\"')
## source PCAP path
PCAP_PATH = os.getenv('PCAP_PATH', '/pcap/').strip()
## buffer size
try:
    FILE_BUFFER = ctypes.c_uint64(ast.literal_eval(os.getenv('FILE_BUFFER'))).value
except (SyntaxError, TypeError, ValueError):
    FILE_BUFFER = 'Files::reassembly_buffer_size'
## size limit
try:
    SIZE_LIMIT = ctypes.c_uint64(ast.literal_eval(os.getenv('SIZE_LIMIT'))).value
except (SyntaxError, TypeError, ValueError):
    SIZE_LIMIT = 'FileExtract::default_limit'
## log in JSON format
JSON_LOGS_ENV = os.getenv('JSON_LOGS')
if JSON_LOGS_ENV is None:
    JSON_LOGS = 'LogAscii::use_json'
else:
    JSON_LOGS_BOOL = BOOLEAN_STATES.get(JSON_LOGS_ENV.casefold())
    if JSON_LOGS_BOOL is None:
        JSON_LOGS = 'LogAscii::use_json'
    else:
        JSON_LOGS = 'T' if JSON_LOGS_BOOL else 'F'

# plugin template
FILE_TEMP = '''\
@load ../__load__.bro

module FileExtraction;

hook FileExtraction::extract(f: fa_file, meta: fa_metadata) &priority=5 {
    if ( meta?$mime_type && meta$mime_type == "%s")
        break;
}
'''

# MIME white list
LOAD_MIME = os.getenv('BRO_MIME')
if LOAD_MIME is not None:
    load_file = list()
    for mime_type in filter(len, re.split(r'\s*[,;|]\s*', LOAD_MIME)):
        safe_mime = re.sub(r'\W', r'-', mime_type, re.ASCII)
        file_name = os.path.join('.', 'plugins', f'extract-{safe_mime}.bro')
        load_file.append(file_name)
        with open(os.path.join(ROOT, 'scripts', file_name), 'w') as zeek_file:
            zeek_file.write(FILE_TEMP % mime_type)
else:
    load_file = [os.path.join('.', 'plugins', 'extract-all-files.bro')]

# protocol list
LOAD_PROTOCOL = os.getenv('BRO_PROTOCOL')
if LOAD_PROTOCOL is not None:
    # available protocols
    available_protocols = ('dtls', 'ftp', 'http', 'irc', 'smtp')
    for protocol in filter(lambda protocol: protocol in available_protocols,
                           re.split(r'\s*[,;|]\s*', LOAD_PROTOCOL.casefold())):
        load_file.append(os.path.join('.', 'hooks', f'extract-{protocol}.bro'))

# prepare regex
MIME_REGEX = re.compile(r'(?P<prefix>\s*redef mime\s*=\s*)[TF](?P<suffix>\s*;\s*)')
LOGS_REGEX = re.compile(r'(?P<prefix>\s*redef logs\s*=\s*").*?(?P<suffix>"\s*;\s*)')
JSON_REGEX = re.compile(r'(?P<prefix>\s*redef use_json\s*=\s*).*?(?P<suffix>\s*;\s*)')
SALT_REGEX = re.compile(r'(?P<prefix>\s*redef file_salt\s*=\s*).*?(?P<suffix>\s*;\s*)')
FILE_REGEX = re.compile(r'(?P<prefix>\s*redef file_buffer\s*=\s*).*?(?P<suffix>\s*;\s*)')
PATH_REGEX = re.compile(r'(?P<prefix>\s*redef path_prefix\s*=\s*).*?(?P<suffix>\s*;\s*)')
SIZE_REGEX = re.compile(r'(?P<prefix>\s*redef size_limit\s*=\s*).*?(?P<suffix>\s*;\s*)')
LOAD_REGEX = re.compile(r'^@load\s+.*?\s*')

# update Bro scripts
context = list()
with open(os.path.join(ROOT, 'scripts', 'config.bro')) as config:
    for line in config:
        line = MIME_REGEX.sub(rf'\g<prefix>{"T" if DUMP_MIME else "F"}\g<suffix>', line)
        line = LOGS_REGEX.sub(rf'\g<prefix>{os.path.join(LOGS_PATH, "processed_mime.log")}\g<suffix>', line)
        line = JSON_REGEX.sub(rf'\g<prefix>{JSON_LOGS}\g<suffix>', line)
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
