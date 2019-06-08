#!/usr/bin/env bash

set -aex

# change curdir
cd /broapt

# load environs
if [ -f .env ] ; then
    source .env
fi

# compose Bro scripts
/usr/bin/python3.6 python/compose.py

# run scripts
/usr/bin/python3.6 python $@

# sleep
sleep infinity
