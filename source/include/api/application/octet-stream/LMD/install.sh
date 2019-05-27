#!/usr/bin/env bash

set -aex

# load environs
if [ -f .env ] ; then
    source .env
fi

# install LMD
cd ./linux-malware-detect/
./install.sh
