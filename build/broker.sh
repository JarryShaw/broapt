#!/usr/bin/env bash

set -ex

# download Broker
rm -f broker-1.1.2.tar.gz
wget https://www.zeek.org/downloads/broker-1.1.2.tar.gz
tar -xzf broker-1.1.2.tar.gz
cd broker-1.1.2

# build & install Broker
mkdir -p $(pipenv --venv)/broker
pipenv run ./configure \
    --prefix=$(pipenv --venv)/broker \
    --python-prefix=$(pipenv run python -c 'import sys; print(sys.exec_prefix)') \
    --with-python=$(pipenv --py) \
    --with-openssl=$(brew --prefix openssl)
pipenv run make install

# remove archives
if which trash >/dev/null 2>&1 ; then
    trash broker-1.1.2 broker-1.1.2.tar.gz
else
    rm -rf broker-1.1.2 broker-1.1.2.tar.gz
fi
