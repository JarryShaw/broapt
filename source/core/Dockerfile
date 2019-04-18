# basic info
FROM library/ubuntu:16.04
LABEL version=2019.04.18

# set up environment variables
ENV LANG "C.UTF-8"
ENV LC_ALL "C.UTF-8"
ENV PYTHONIOENCODING "UTF-8"
ENV PATH="/usr/local/bro/bin:${PATH}"
ENV PYTHONPATH="/usr/lib/python3.5/site-packages"

# install, Bro, Python 3 & all requirements
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
    make \
    ## python3 is actually dependency of the latters
    ## but we keep it here as a good remainder
    python3 \
    python3-magic \
    python3-pip \
    ## prerequisites for installing Bro
    ## from https://docs.zeek.org/en/stable/install/install.html#prerequisites
    libpcap-dev \
    libssl-dev \
    python3-dev \
    zlib1g-dev

# install Bro
COPY vendor/archive/bro-2.6.1.ubuntu.16.04.tar.gz /tmp/bro.tar.gz
RUN tar -xvzf /tmp/bro.tar.gz \
    -C /usr/local

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
    ## Bro archive
    /tmp/bro.tar.gz \
    ## Python dependencies
    /tmp/python \
    /tmp/pip \
    && apt-get autoremove -y \
    && apt-get autoclean \
    && apt-get clean
