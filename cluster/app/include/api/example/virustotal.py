# -*- coding: utf-8 -*-

import json
import os
import pprint
import sys
import time

import requests

# useful paths
LOGS_PATH = os.getenv('BROAPT_LOGS_PATH', '/var/log/bro/')
VT_LOG = os.getenv('VT_LOG', '/var/log/bro/tmp/')
os.makedirs(VT_LOG, exist_ok=True)

# VirusTotal API key
try:
    VT_API = os.environ['VT_API']
except KeyError:
    print('API key for VirusTotal is required.', file=sys.stderr)
    raise

# time interval
try:
    VT_INT = int(os.getenv('VT_INTERVAL'))
except (TypeError, ValueError):
    VT_INT = 60

# max retry
try:
    VT_RETRY = int(os.getenv('VT_RETRY'))
except (TypeError, ValueError):
    VT_RETRY = 3

# ratio threshold percentage
try:
    VT_PERCENT = int(os.getenv('VT_PERCENT'))
except (TypeError, ValueError):
    VT_PERCENT = 50

# return codes
EXIT_SUCCESS = 0
EXIT_FAILURE = 408  # Request Timeout

# file size threshold
MAX_SIZE = 32e6  # 32M


def log_response(response):
    print(f'+ [{response.status_code}] {response.request.method} {response.url}')
    try:
        pprint.pprint(response.json())
    except json.JSONDecodeError:
        print(response.text)


def main():
    mime = os.environ['BROAPT_MIME']  # pylint: disable=unused-variable
    path = os.environ['BROAPT_PATH']
    name = os.path.split(path)[1]

    size = os.stat(path).st_size
    if size >= MAX_SIZE:
        VT_REQUEST = requests.get('https://www.virustotal.com/vtapi/v2/file/scan/upload_url',
                                  params={'apikey': VT_API})
        log_response(VT_REQUEST)
        if VT_REQUEST.status_code != 200:
            return VT_REQUEST.status_code
        VT_URL = VT_REQUEST.json()['upload_url']
    else:
        VT_URL = 'https://www.virustotal.com/vtapi/v2/file/scan'

    with open(path, 'rb') as file:
        VT_RESPONSE = requests.post(VT_URL,
                                    files={'file': (name, file)},
                                    params={'apikey': VT_API})
    log_response(VT_RESPONSE)
    if VT_RESPONSE.status_code != 200:
        return VT_RESPONSE.status_code
    response_json = VT_RESPONSE.json()

    for _ in range(VT_RETRY):
        VT_REPORT = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
                                 params={'apikey': VT_API,
                                         'resource': response_json['scan_id']})
        log_response(VT_REPORT)
        if VT_REPORT.status_code == 200:
            report_json = VT_REPORT.json()
            if report_json['response_code'] == 1:
                break
        time.sleep(VT_INT)
    else:
        return EXIT_FAILURE

    log_name = f'{os.path.splitext(name)[0]}.json'
    with open(os.path.join(VT_LOG, log_name), 'w') as log:
        json.dump(report_json, log, indent=2)

    positives = report_json['positives']
    total = report_json['total']
    ratio = positives * 100 / total
    rate = ratio >= VT_PERCENT

    result = {'time': time.time(),
              'path': path,
              'mime': mime,
              'rate': rate}
    with open(os.path.join(LOGS_PATH, 'processed_rate.log'), 'at', 1) as file:
        print(json.dumps(result), file=file)
    return EXIT_SUCCESS


if __name__ == '__main__':
    sys.exit(main())
