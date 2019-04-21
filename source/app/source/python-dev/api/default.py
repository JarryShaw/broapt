# -*- coding: utf-8 -*-

import json
import os
import sys
import time

import requests

# useful paths
LOGS_PATH = os.getenv('VT_LOG', '/var/log/bro/tmp/').strip()
os.makedirs(LOGS_PATH, exist_ok=True)

# VirusTotal
VT_API = os.environ['VT_API']

# time interval
try:
    VT_INT = int(os.getenv('VT_INT', '60'))
except ValueError:
    VT_INT = 60

# max retry
try:
    VT_RETRY = int(os.getenv('VT_RETRY', '3'))
except ValueError:
    VT_RETRY = 3

# return codes
EXIT_SUCCESS = 0
EXIT_FAILURE = 408  # Request Timeout

# file size threshold
MAX_SIZE = 32e6  # 32M


def main():
    ## sys.executable
    ## [0] __file__
    ## [1] path_to_file
    ## [2] name_of_file
    ## [3] mime_of_file

    path = sys.argv[1]
    name = sys.argv[2]
    mime = sys.argv[3]  # pylint: disable=unused-variable

    size = os.stat(path).st_size
    if size >= MAX_SIZE:
        VT_REQUEST = requests.get('https://www.virustotal.com/vtapi/v2/file/scan/upload_url',
                                  params={'apikey': VT_API})
        if VT_REQUEST.status_code != 200:
            return VT_REQUEST.status_code
        VT_URL = VT_REQUEST.json()['upload_url']
    else:
        VT_URL = 'https://www.virustotal.com/vtapi/v2/file/scan'

    with open(path, 'rb') as file:
        VT_RESPONSE = requests.post(VT_URL,
                                    files={'file': (name, file)},
                                    params={'apikey': VT_API})

    if VT_RESPONSE.status_code == 200:
        response_json = VT_RESPONSE.json()

        for _ in range(VT_RETRY):
            VT_REPORT = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
                                     params={'apikey': VT_API,
                                             'resource': response_json['scan_id']})
            if VT_REPORT.status_code == 200:
                report_json = VT_REPORT.json()
                if report_json['response_code'] == 1:
                    break
            time.sleep(VT_INT)
        else:
            return EXIT_FAILURE

        log_name = f'{os.path.splitext(name)[0]}.json'
        with open(os.path.join(LOGS_PATH, log_name), 'w') as log:
            json.dump(report_json, log, indent=2)
        return EXIT_SUCCESS
    return VT_RESPONSE.status_code


if __name__ == '__main__':
    sys.exit(main())
