# -*- coding: utf-8 -*-

import csv
import os
import re
import sys

if sys.version_info.major > 2:
    from urllib.request import urlopen
else:
    from urllib import urlopen  # pylint: disable=no-name-in-module

# repo root path
ROOT = os.path.realpath(os.path.dirname(__file__))

# HTTP header names
HTTP_METHODS = list()

# HTTP method regex
METHOD_REGEX = re.compile(r'^[A-Za-z]+$', re.ASCII)

# see https://www.iana.org/assignments/http-methods/http-methods.xhtml
url = 'https://www.iana.org/assignments/http-methods/methods.csv'
page = urlopen(url)
data = page.read().decode('utf-8').strip().splitlines()
page.close()

reader = csv.reader(data)
header = next(reader)

for (method, _, _, _) in reader:
    if METHOD_REGEX.match(method.strip()) is None:
        continue
    HTTP_METHODS.append(method.strip().upper())

# generate Bro file
FILE = '''\
module HTTP;

export {
    ## HTTP Method Registry from IANA
    ## https://www.iana.org/assignments/http-methods/http-methods.xhtml
    redef HTTP::http_methods += {
        %s
    };
}
''' % '\n        '.join(sorted('"%s",' % method for method in set(HTTP_METHODS)))

# update Bro script
with open(os.path.join(ROOT, '..', 'include', 'scripts', 'const', 'http-methods.bro'), 'w') as file:
    file.write(FILE)
