#!/usr/bin/env bash

set -ex

# download Bro
wget https://www.zeek.org/downloads/bro-2.6.1.tar.gz -O bro-2.6.1.tar.gz
tar -xzf bro-2.6.1.tar.gz
cd bro-2.6.1

# build & install Bro
mkdir -p $(pipenv --venv)/{bro,var,etc}
pipenv run ./configure \
    --prefix=$(pipenv --venv)/bro \
    --localstatedir=$(pipenv --venv)/var \
    --conf-files-dir=$(pipenv --venv)/etc \
    --with-openssl=$(brew --prefix openssl)
pipenv run make
pipenv run make install

# remove arhives
cd ..
if which trash >/dev/null 2>&1 ; then
    trash bro-2.6.1 bro-2.6.1.tar.gz
else
    rm -rf bro-2.6.1 bro-2.6.1.tar.gz
fi
