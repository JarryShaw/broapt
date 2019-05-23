#!/usr/bin/env bash

set -ex

cd ./elfparser/
mkdir build
cd build/
cmake ..
make
