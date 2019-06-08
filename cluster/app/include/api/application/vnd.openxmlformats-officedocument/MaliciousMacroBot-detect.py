# -*- coding: utf-8 -*-

import json
import os
import sys
import time

from mmbot import MaliciousMacroBot

# useful paths
LOGS_PATH = os.getenv('BROAPT_LOGS_PATH', '/var/log/bro/')
MMB_LOG = os.getenv('MMB_LOG', '/var/log/bro/tmp/')
os.makedirs(MMB_LOG, exist_ok=True)

# prediction mapping
MMB_MAP = dict(
    benign=False,
    malicious=True,
)

# return codes
EXIT_SUCCESS = 0
EXIT_FAILURE = 1


def main():
    mmb = MaliciousMacroBot()
    if not mmb.mmb_init_model():
        return EXIT_FAILURE

    mime = os.environ['BROAPT_MIME']
    path = os.environ['BROAPT_PATH']
    name = os.path.split(path)[1]

    # run prediction
    prediction = mmb.mmb_predict(path, datatype='filepath')
    records = prediction.to_dict(orient='records')

    log_name = f'{os.path.splitext(name)[0]}.json'
    with open(os.path.join(MMB_LOG, log_name), 'w') as log:
        json.dump(records, log, indent=2)

    result = {'time': time.time(),
              'path': path,
              'mime': mime,
              'rate': MMB_MAP[prediction.loc[0].prediction]}
    with open(os.path.join(LOGS_PATH, 'rate.log'), 'at', 1) as file:
        print(json.dumps(result), file=file)
    return EXIT_SUCCESS


if __name__ == '__main__':
    sys.exit(main())
