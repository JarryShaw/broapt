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
FTP_COMMANDS = list()

# see https://www.iana.org/assignments/ftp-commands-extensions/ftp-commands-extensions.xhtml
url = 'https://www.iana.org/assignments/ftp-commands-extensions/ftp-commands-extensions-2.csv'
page = urlopen(url)
data = page.read().decode('utf-8').strip().splitlines()
page.close()

reader = csv.reader(data)
header = next(reader)

for (command, _, _, _, _, _) in reader:
    if command.strip().upper() == '-N/A-':
        continue
    FTP_COMMANDS.append(command.strip().upper())

# generate Bro file
FILE = '''\
module FTP;

export {
    ## FTP Commands and Extensions from IANA
    ## https://www.iana.org/assignments/ftp-commands-extensions/ftp-commands-extensions.xhtml
    redef FTP::logged_commands += {
        %s
    };
}
''' % '\n        '.join(sorted('"%s",' % command for command in set(FTP_COMMANDS)))

# update Bro script
with open(os.path.join(ROOT, '..', 'include', 'scripts', 'const', 'ftp-commands.bro'), 'w') as file:
    file.write(FILE)
