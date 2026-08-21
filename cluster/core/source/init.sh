#!/usr/bin/env bash

set -aex

# change cwd
cd /source

# load environs
if [ -f .env ] ; then
    source .env
fi

# compose Bro scripts
python3 python/compose.py

# run scripts
python3 python "$@"

# sleep
sleep infinity
