#!/usr/bin/env bash

set -aex

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
