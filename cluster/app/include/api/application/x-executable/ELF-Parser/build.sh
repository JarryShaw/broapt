#!/usr/bin/env bash

set -aex

# load environs
if [ -f .env ] ; then
    source .env
fi

# prepare directories
cd ./elfparser/
mkdir build
cd ./build/

# run build process
cmake ..
make
make install
