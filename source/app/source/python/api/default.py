# -*- coding: utf-8 -*-

import json
import os
import sys

import requests

# useful paths
MODEL_PATH = os.getenv('MODEL_PATH', '/model/')  # pylint: disable=unused-variable
LOGS_PATH = os.getenv('LOGS_PATH', '/var/log/bro/').strip()

# VirusTotal
VT_API = os.environ['VT_API']
VT_URL = 'https://www.virustotal.com/vtapi/v2/file/scan'
VT_PARAM = {'apikey': VT_API}


def main():
    ## sys.executable
    ## __file__
    ## path_to_file
    ## name_of_file
    ## mime_of_file

    path = sys.argv[1]
    name = sys.argv[2]
    mime = sys.argv[3]  # pylint: disable=unused-variable

    with open(path, 'rb') as file:
        VT_FILES = {'file': (name, file)}
        VT_RESPONSE = requests.post(VT_URL,
                                    files=VT_FILES,
                                    params=VT_PARAM)

    if VT_RESPONSE.status_code == 200:
        VT_JSON = VT_RESPONSE.json()

        log_name = '{}.json'.format(os.path.split(name)[0])
        with open(os.path.join(LOGS_PATH, log_name)) as log:
            json.dump(VT_JSON, log)
        return 0
    return 1


if __name__ == '__main__':
    sys.exit(main())
