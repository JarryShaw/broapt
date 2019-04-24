# -*- coding: utf-8 -*-

from __future__ import print_function

import mimetypes
import os
import re
import sys

if sys.version_info.major > 2:
    raw_input = input

# repo root path
ROOT = os.path.realpath(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

# Bro table literal
TABLE = re.compile(r'\s*\["(?P<mime>.+?)"\] = "(?P<ext>.+?)",\s*')

# mime2ext mappings
mime2ext = dict()
with open(os.path.join(ROOT, 'scripts', 'file-extensions.bro')) as file:
    for line in file:
        match = TABLE.match(line)
        if match is None:
            continue
        mime2ext[match.group('mime')] = match.group('ext')


# parse missing mappings
missing = list()
LOGS_PATH = os.getenv('LOGS_PATH', '/var/log/bro')
with open(os.path.join(LOGS_PATH, 'processed_mime.log')) as file:
    missing.extend(filter(lambda mime: mime not in mime2ext, map(lambda line: line.strip(), file)))

# update missing mappings
for mime in set(missing):
    ext = [s.lstrip('.') for s in mimetypes.guess_all_extensions(mime)]
    if ext:
        if len(ext) > 1:
            print(f'{mime!r} -> {" | ".join(ext)}')
            try:
                usr_ext = raw_input('Please select an extension: ').strip().lstrip('.')
            except (EOFError, KeyboardInterrupt):
                pass
            else:
                mime2ext[mime] = usr_ext
        else:
            mime2ext[mime] = ext[0]
    else:
        try:
            usr_ext = raw_input(f'[{mime}] Please input an possible extension: ').strip().lstrip('.')
        except (EOFError, KeyboardInterrupt):
            pass
        else:
            mime2ext[mime] = usr_ext

# generate Bro file
TEXT = '\n        '.join(sorted(f'["{mime}"] = "{ext}",' for mime, ext in mime2ext.items()))
FILE = '''\
module FileExtraction;

export {
    ## Map file extensions to file mime_type
    const mime_to_ext: table[string] of string = {
        %s
    };
}
''' % TEXT

# update Bro script
with open(os.path.join(ROOT, 'scripts', 'file-extensions.bro'), 'w') as file:
    file.write(FILE)
