# -*- coding: utf-8 -*-
# pylint: disable=import-error, no-name-in-module

import dataclasses
import functools
import multiprocessing
import os
import re
import sys
import time

from .const import CPU_CNT, DUMP_PATH, FILE, INTERVAL
from .process import process

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


# mimetype class
@dataclasses.dataclass
class MIME:
    media_type: str
    subtype: str
    name: str


# entry class
@functools.total_ordering
@dataclasses.dataclass
class Entry:
    path: str
    uuid: str
    mime: MIME

    def __lt__(self, value):
        return self.path < value.path


def listdir(path):
    file_list = list()
    for entry in os.scandir(path):
        if entry.is_dir():
            file_list.extend(listdir(entry.path))
        else:
            match = FILE_REGEX.match(entry.name)
            if match is None:
                continue
            media_type = match.group('media_type')
            subtype = match.group('subtype')
            mime = MIME(media_type=media_type,
                        subtype=subtype,
                        name=f'{media_type}/{subtype}'.lower())
            file_list.append(Entry(path=entry.path, uuid=match.group('fuid'), mime=mime))
    return file_list


def main():
    # processed log
    processed_file = list()
    if os.path.isfile(FILE):
        with open(FILE) as file:
            processed_file.extend(line.strip() for line in file)

    # main loop
    while True:
        try:
            file_list = sorted(filter(lambda entry: entry.path not in processed_file, listdir(DUMP_PATH)))
            if file_list:
                if CPU_CNT <= 1:
                    [process(entry) for entry in file_list]  # pylint: disable=expression-not-assigned
                else:
                    multiprocessing.Pool(CPU_CNT).map(process, file_list)
            time.sleep(INTERVAL)
        except KeyboardInterrupt:
            return 0
        processed_file.extend(map(lambda entry: entry.path, file_list))
        print('+ Starting another turn...')


if __name__ == '__main__':
    sys.exit(main())
