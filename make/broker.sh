#!/usr/bin/env bash

set -ex

# download Broker
if [ ! -f broker-1.1.2.tar.gz ] ; then
    wget https://www.zeek.org/downloads/broker-1.1.2.tar.gz -O broker-1.1.2.tar.gz
fi
tar -xzf broker-1.1.2.tar.gz
cd broker-1.1.2

# modify configure
pipenv run python << EOF
# -*- coding: utf-8 -*-

PYTHON_EXECUTABLE="PYTHON_EXECUTABLE:PATH=$(pipenv --py)"
PYTHON_CONFIG="PYTHON_CONFIG:PATH=$(pipenv --venv)/bin/python-config"

context = []
with open('configure', 'r') as file:
    for line in file:
        if line == 'CMakeCacheEntries=""\n':
            context.append('CMakeCacheEntries=" -D %s -D %s"\n' % (PYTHON_EXECUTABLE, PYTHON_CONFIG))
        else:
            context.append(line)

with open('configure', 'w') as file:
    file.writelines(context)
EOF
chmod +x configure

# build & install Broker
mkdir -p $(pipenv --venv)/broker
pipenv run ./configure \
    --prefix=$(pipenv --venv)/broker \
    --python-prefix=$(pipenv run python -c 'import sys; print(sys.exec_prefix)') \
    --with-python=$(pipenv --py) \
    --with-bro=$(brew --prefix bro)/bin/bro \
    --with-openssl=$(brew --prefix openssl)
pipenv run make install

# remove archives
cd ..
if which trash >/dev/null 2>&1 ; then
    trash broker-1.1.2 broker-1.1.2.tar.gz
else
    rm -rf broker-1.1.2 broker-1.1.2.tar.gz
fi
