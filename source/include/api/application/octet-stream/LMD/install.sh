#!/usr/bin/env bash

set -aex

# load environs
if [ -f .env ] ; then
    source .env
fi

# install chkconfig
# from https://uni.edu/~prefect/devel/chkconfig/index.shtml
[ `which chkconfig` ] || cp chkconfig /usr/local/bin/chkconfig

# install LMD
cd ./linux-malware-detect/
./install.sh
