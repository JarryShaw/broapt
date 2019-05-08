# basic info
FROM library/ubuntu:16.04
LABEL version=2019.05.08

# set up environment variables
ENV LANG "C.UTF-8"
ENV LC_ALL "C.UTF-8"
ENV PYTHONIOENCODING "UTF-8"

# install, Bro, Python 3 & all requirements
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        software-properties-common \
 && add-apt-repository --yes ppa:deadsnakes/ppa
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ## python3.6 is actually dependency of the latters
        ## but we keep it here as a good remainder
        python3.6 \
        python3-pip \
        python3-setuptools \
        python3-wheel \
        ## do not directly install python3-yaml
        ## install its dependency libyaml instead
        # python3-yaml \
        libyaml-0-2 \
 && ln -sf /usr/bin/python3.6 /usr/bin/python3

# install Python packages & dependencies
COPY vendor/python /tmp/python
RUN python3 -m pip install --no-deps --cache-dir=/tmp/pip \
        /tmp/python/pip-* \
        /tmp/python/setuptools-* \
        /tmp/python/wheel-* \
 && rm -f \
        /tmp/python/pip-* \
        /tmp/python/setuptools-* \
        /tmp/python/wheel-* \
 && python3 -m pip install --no-deps --cache-dir=/tmp/pip \
        /tmp/python/*

# copy source
COPY source /source

# cleanup process
RUN rm -rf \
        ## apt repository lists
        /var/lib/apt/lists/* \
        ## Python dependencies
        /tmp/python \
        /tmp/pip \
 && python3 -m pip uninstall -y \
        wheel \
        setuptools \
        pip \
 && apt-get remove -y --auto-remove \
        software-properties-common \
        python3-pip \
        python3-setuptools \
        python3-wheel \
 && apt-get autoremove -y \
 && apt-get autoclean \
 && apt-get clean

# final setup
RUN ln -sf /usr/bin/python3.6 /usr/bin/python3
