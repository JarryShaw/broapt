#!/usr/bin/env bash

set -ex

# download Bro
if [ ! -f bro-2.6.1.tar.gz ] ; then
    wget https://www.zeek.org/downloads/bro-2.6.1.tar.gz -O bro-2.6.1.tar.gz
fi
tar -xzf bro-2.6.1.tar.gz
cd bro-2.6.1

# build & install Bro
mkdir -p $(pipenv --venv)/{bro,var,etc}
pipenv run ./configure \
    --prefix=$(pipenv --venv)/bro \
    --localstatedir=$(pipenv --venv)/var \
    --conf-files-dir=$(pipenv --venv)/etc \
    --with-openssl=$(brew --prefix openssl) \
    --with-bison=$(brew --prefix bison)/bin/bison \
    --with-python=$(pipenv --py) \
    --with-geoip=$(brew --prefix geoip) \
    --with-swig=$(brew --prefix swig)/bin/swig
pipenv run make
pipenv run make install

# remove arhives
cd ..
if which trash >/dev/null 2>&1 ; then
    trash bro-2.6.1 bro-2.6.1.tar.gz
else
    rm -rf bro-2.6.1 bro-2.6.1.tar.gz
fi
