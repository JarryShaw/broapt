# -*- coding: utf-8 -*-

import mimetypes
import os
import pathlib
import re

# repo root path
ROOT = str(pathlib.Path(__file__).parents[1].resolve())

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

# mimetypes database
mimetypes.init()
mappings = mimetypes._db.types_map_inv[0]  # pylint: disable=protected-access
mappings.update(mimetypes._db.types_map_inv[1])  # pylint: disable=protected-access

# update mappings
for mime, ext in mappings.items():
    pure_ext = [s.lstrip('.') for s in ext]
    if mime in mime2ext:
        bro_ext = mime2ext[mime]
        if bro_ext not in pure_ext:
            pure_ext.append(bro_ext)
    if len(pure_ext) > 1:
        print(f'{mime!r} -> {" | ".join(pure_ext)}')
        usr_ext = input('Please select an extension: ').strip().lstrip('.')
        if usr_ext:
            mime2ext[mime] = usr_ext
    else:
        mime2ext[mime] = ext[0].lstrip('.')

# generate Bro file
TEXT = '\n        '.join(sorted(f'["{mime}"] = "{ext}",' for mime, ext in mime2ext.items()))
FILE = f'''\
module FileExtraction;

export {{
    ## Map file extensions to file mime_type
    const mime_to_ext: table[string] of string = {{
        {TEXT}
    }};
}}
'''

# update Bro script
with open(os.path.join(ROOT, 'scripts', 'file-extensions.bro'), 'w') as file:
    file.write(FILE)
