# -*- coding: utf-8 -*-

import csv
import os
import sys

if sys.version_info.major > 2:
    from urllib.request import urlopen
else:
    from urllib import urlopen  # pylint: disable=no-name-in-module

# repo root path
ROOT = os.path.realpath(os.path.dirname(__file__))

# HTTP header names
HEADER_NAMES = list()

# see https://www.iana.org/assignments/message-headers/message-headers.xml
URLS = ['https://www.iana.org/assignments/message-headers/perm-headers.csv',
        'https://www.iana.org/assignments/message-headers/prov-headers.csv']
for url in URLS:
    page = urlopen(url)
    data = page.read().decode('utf-8').strip().splitlines()
    page.close()

    reader = csv.reader(data)
    header = next(reader)

    for (field, _, protocol, _, _) in reader:
        if protocol.strip().casefold() != 'http':
            continue
        HEADER_NAMES.append(field.strip().upper())

# generate Bro file
FILE = '''\
module HTTP;

export {
    ## Message Headers from IANA
    ## https://www.iana.org/assignments/message-headers/message-headers.xml
    option header_names: set[string] = {
        %s
    };
}
''' % '\n        '.join(sorted('"%s",' % field for field in set(HEADER_NAMES)))

# update Bro script
with open(os.path.join(ROOT, '..', 'include', 'scripts', 'const', 'http-header-names.bro'), 'w') as file:
    file.write(FILE)
