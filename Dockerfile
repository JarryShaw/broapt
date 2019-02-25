# basic info
FROM library/ubuntu:18.04
LABEL version=2019.02.25

# set up environment variables
ENV LANG "C.UTF-8"
ENV LC_ALL "C.UTF-8"
ENV PYTHONIOENCODING "UTF-8"

# install Python 3 & all requirements
RUN apt-get update \
 && apt-get install -y \
       bro \
       python3 \
       python3-pip \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# install Python packages & dependencies
COPY vendor/python/download /tmp/python
RUN python3 -m pip install --no-deps --cache-dir=/tmp/pip \
       /tmp/python/pip-* \
       /tmp/python/setuptools-* \
       /tmp/python/wheel-* \
 && rm -f /tmp/python/pip-* \
           /tmp/python/setuptools-* \
           /tmp/python/wheel-* \
 && python3 -m pip install --no-deps --cache-dir=/tmp/pip \
       /tmp/python/* \
 && rm -rf /tmp/pip /tmp/python

# copy source files
COPY vendor/file-extraction /vendor/file-extraction
COPY sample /sample
COPY test /test
