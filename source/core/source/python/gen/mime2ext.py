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

# force update flag
BOOLEAN_STATES = {'1': True, '0': False,
                  'yes': True, 'no': False,
                  'true': True, 'false': False,
                  'on': True, 'off': False}
FLAG = BOOLEAN_STATES.get(os.getenv('MIME_UPDATE', 'false').strip().lower(), False)

# mime2ext mappings
mime2ext = dict()
with open(os.path.join(ROOT, 'scripts', 'file-extensions.bro')) as file:
    for line in file:
        match = TABLE.match(line)
        if match is None:
            continue
        mime2ext[match.group('mime')] = match.group('ext')

# mimetypes database
mimetypes.init()
mappings = mimetypes._db.types_map_inv[0]  # pylint: disable=protected-access
mappings.update(mimetypes._db.types_map_inv[1])  # pylint: disable=protected-access

# update mappings
for mime, ext in mappings.items():
    pure_ext = [s.lstrip('.') for s in ext]
    if mime in mime2ext:
        if FLAG:
            bro_ext = mime2ext[mime]
            if bro_ext not in pure_ext:
                pure_ext.append(bro_ext)
        else:
            continue
    if len(pure_ext) > 1:
        print('{!r} -> {}'.format(mime, " | ".join(pure_ext)))
        usr_ext = raw_input('Please select an extension: ').strip().lstrip('.')
        if usr_ext:
            mime2ext[mime] = usr_ext
    else:
        mime2ext[mime] = ext[0].lstrip('.')

# generate Bro file
TEXT = '\n        '.join(sorted('["{}"] = "{}",'.format(mime, ext) for mime, ext in mime2ext.items()))
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
