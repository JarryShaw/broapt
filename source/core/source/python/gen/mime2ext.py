# -*- coding: utf-8 -*-

from __future__ import print_function

import csv
import json
import mimetypes
import os
import re
import sys
import traceback

if sys.version_info.major > 2:
    raw_input = input
    from urllib.request import urlopen
else:
    from urllib import urlopen  # pylint: disable=no-name-in-module

# repo root path
ROOT = os.path.realpath(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

# Bro table literal
TABLE = re.compile(r'\s*\["(?P<mime>.+?)"\] = "(?P<ext>.+?)",\s*')

# MIME type literal
MIME_REGEX = re.compile(r'\S+/\S+')
MIME_EXT_REGEX = re.compile(r'\S+/\S+\+(?P<ext>\S+)')

# force update flag
BOOLEAN_STATES = {'1': True, '0': False,
                  'yes': True, 'no': False,
                  'true': True, 'false': False,
                  'on': True, 'off': False}
FLAG = BOOLEAN_STATES.get(os.getenv('BROAPT_FORCE_UPDATE', 'false').strip().lower(), False)


class Dict(dict):

    def __setitem__(self, key, value):
        return super().__setitem__(key.lower(), value.lower())


# mime2ext mappings
mime2ext = Dict()
with open(os.path.join(ROOT, 'scripts', 'file-extensions.bro')) as file:
    for line in file:
        match = TABLE.match(line.lower())
        if match is None:
            continue
        mime2ext[match.group('mime')] = match.group('ext')

JSON = os.path.join(ROOT, 'python', 'gen', 'tmp', 'db.json')
if os.path.isfile(JSON):
    with open(JSON) as file:
        mime2ext.update(json.load(file))
try:
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
            print('%r -> %s' % (mime, ' | '.join(pure_ext)))
            try:
                usr_ext = raw_input('Please select an extension: ').strip().lstrip('.')
            except (EOFError, KeyboardInterrupt):
                print()
            else:
                mime2ext[mime] = usr_ext
        else:
            mime2ext[mime] = ext[0].lstrip('.')

    # see https://www.iana.org/assignments/media-types/media-types.xhtml
    URLS = ['https://www.iana.org/assignments/media-types/application.csv',
            'https://www.iana.org/assignments/media-types/audio.csv',
            'https://www.iana.org/assignments/media-types/font.csv',
            'https://www.iana.org/assignments/media-types/image.csv',
            'https://www.iana.org/assignments/media-types/message.csv',
            'https://www.iana.org/assignments/media-types/model.csv',
            'https://www.iana.org/assignments/media-types/multipart.csv',
            'https://www.iana.org/assignments/media-types/text.csv',
            'https://www.iana.org/assignments/media-types/video.csv']
    for url in URLS:
        page = urlopen(url)
        data = page.read().decode('utf-8').lower().strip().splitlines()
        page.close()

        reader = csv.reader(data)
        header = next(reader)

        for (_, mime, _) in reader:
            if MIME_REGEX.match(mime) is None:
                print('Invalid MIME type: %r' % mime)
                continue
            if mime in mime2ext:
                continue
            ext = mappings.get(mime)
            if ext is None:
                # .../...+...
                match = MIME_EXT_REGEX.match(mime)
                if match is not None:
                    ext = match.group('ext').lower()
                    if ext in mime2ext.values():
                        mime2ext[mime] = ext
                        continue
                # .../XXX
                if len(mime) <= 3:
                    mime2ext[mime] = ext
                    continue
                # .../...-...
                guess_ext = re.split(r'[.+-]', mime.lower().split('/', maxsplit=1)[1])[-1]
                if guess_ext in mime2ext.values():
                    mime2ext[mime] = guess_ext
                    continue
                try:
                    usr_ext = raw_input('[%s] Please input an possible extension: ' % mime).strip().lstrip('.')
                except (EOFError, KeyboardInterrupt):
                    print()
                else:
                    mime2ext[mime] = usr_ext
            else:
                pure_ext = [s.lstrip('.') for s in ext]
                if len(pure_ext) > 1:
                    print('%r -> %s' % (mime, ' | '.join(pure_ext)))
                    try:
                        usr_ext = raw_input('Please select an extension: ').strip().lstrip('.')
                    except (EOFError, KeyboardInterrupt):
                        print()
                    else:
                        mime2ext[mime] = usr_ext
                else:
                    mime2ext[mime] = ext[0].lstrip('.')
except BaseException:
    traceback.print_exc()
finally:
    os.makedirs(os.path.dirname(JSON), exist_ok=True)
    with open(JSON, 'w') as file:
        json.dump(mime2ext, file, indent=2)

# generate Bro file
FILE = '''\
module FileExtraction;

export {
    ## Map file extensions to file mime_type
    const mime_to_ext: table[string] of string = {
        %s
    };
}
''' % '\n        '.join(sorted('["%s"] = "%s",' % (mime, ext) for mime, ext in mime2ext.items()))

# update Bro script
with open(os.path.join(ROOT, 'scripts', 'file-extensions.bro'), 'w') as file:
    file.write(FILE)
