# -*- coding: utf-8 -*-

import json
import os
import shutil
import subprocess
import sys
import time

# environ
PYTHON27 = os.environ['PYTHON27']
ROOT = os.path.realpath(os.path.dirname(__file__))

# useful paths
LOGS_PATH = os.getenv('BROAPT_LOGS_PATH', '/var/log/bro/')
APK_LOG = os.getenv('APK_LOG', '/var/log/bro/tmp/')
os.makedirs(APK_LOG, exist_ok=True)

# return codes
EXIT_SUCCESS = 0
EXIT_FAILURE = 1


def main():
    mime = os.environ['BROAPT_MIME']
    path = os.environ['BROAPT_PATH']
    name = os.path.split(path)[1]

    dirname = os.path.splitext(name)[0]
    tempdir = os.path.join(APK_LOG, dirname)

    # move target to a temporary directory
    shutil.copyfile(path, os.path.join(tempdir, name))

    # prepare arguments
    args = [PYTHON27, 'androPyTool.py', '-s', tempdir]
    args.extend(sys.argv[1:])

    # prepare environment
    cwd = os.path.join(ROOT, 'AndroPyTool')
    env = os.environ

    # run command
    subprocess.check_call(args, cwd=cwd, env=env)

    # check output
    if os.path.exists(os.path.join(tempdir, 'MW', name)):
        rate = True
    elif os.path.exists(os.path.join(tempdir, 'BW', name)):
        rate = False
    else:
        return EXIT_FAILURE

    result = {'time': time.time(),
              'path': path,
              'mime': mime,
              'rate': rate}
    with open(os.path.join(LOGS_PATH, 'rate.log'), 'at', 1) as file:
        print(json.dumps(result), file=file)
    return EXIT_SUCCESS


if __name__ == '__main__':
    sys.exit(main())
