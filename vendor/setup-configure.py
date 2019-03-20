# -*- coding: utf-8 -*-

import os

ROOT = os.dirname(os.path.abspath(__file__))

PYTHON_EXECUTABLE = "PYTHON_EXECUTABLE:PATH=$(pipenv --py)"
PYTHON_CONFIG = "PYTHON_CONFIG:PATH=$(pipenv --venv)/bin/python-config"

context = []
with open(os.path.join(ROOT, 'configure'), 'r') as file:
    for line in file:
        if line == 'CMakeCacheEntries=""\n':
            context.append('CMakeCacheEntries=" -D %s -D %s"\n' % (PYTHON_EXECUTABLE, PYTHON_CONFIG))
        else:
            context.append(line)

with open(os.path.join(ROOT, 'configure'), 'w') as file:
    file.writelines(context)
