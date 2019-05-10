#!/usr/bin/env bash

set -ax

# change cwd
cd /source

# load environs
if [ -f .env ] ; then
    source .env
fi

# run scripts
/usr/bin/python3.6 python

# sleep
sleep infinity
