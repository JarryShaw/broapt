#!/usr/bin/env bash

set -ax

# change cwd
cd /source

# load environs
if [ -f .env ] ; then
    source .env
fi

# setup symlink
ln -sf /source/python/const.py /source/python/sites/
ln -sf /source/python/logparser.py /source/python/sites/
ln -sf /source/python/utils.py /source/python/sites/

# run scripts
/usr/bin/python3.6 python $@

# sleep
sleep infinity
