# -*- coding: utf-8 -*-

PYTHON_EXECUTABLE = "PYTHON_EXECUTABLE:PATH=$(pipenv --py)"
PYTHON_CONFIG = "PYTHON_CONFIG:PATH=$(pipenv --venv)/bin/python-config"

context = []
with open('configure', 'r') as file:
    for line in file:
        if line == 'CMakeCacheEntries=""\n':
            context.append('CMakeCacheEntries=" -D %s -D %s"\n' % (PYTHON_EXECUTABLE, PYTHON_CONFIG))
        else:
            context.append(line)

with open('configure', 'w') as file:
    file.writelines(context)
