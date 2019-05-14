# -*- coding: utf-8 -*-

import os
import shutil
import subprocess
import sys
import tempfile

# environ
PYTHON27 = os.environ['PYTHON27']
ROOT = os.path.realpath(os.path.dirname(__file__))

# macros
mime = os.environ['BROAPT_MIME']  # pylint: disable=unused-variable
path = os.environ['BROAPT_PATH']
name = os.path.split(path)[1]

with tempfile.TemporaryDirectory() as tempdir:
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
