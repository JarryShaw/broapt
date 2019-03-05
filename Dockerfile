# basic info
FROM library/ubuntu:16.04
LABEL version=2019.03.05

# set up environment variables
ENV LANG "C.UTF-8"
ENV LC_ALL "C.UTF-8"
ENV PYTHONIOENCODING "UTF-8"

# install, Bro, Python 3 & all requirements
RUN apt-get update \
 && apt-get upgrade -y \
 && apt-get install -y \
        wget \
        ## python3 is actually dependency of the latters
        ## but we keep it here as a good remainder
        python3 \
        python3-magic \
        python3-pip \
        ## prerequisites for building Bro & Broker
        ## from https://docs.zeek.org/en/stable/install/install.html#prerequisites
        cmake \
        make \
        gcc \
        g++ \
        flex \
        bison \
        libpcap-dev \
        libssl-dev \
        # python-dev \
        swig \
        zlib1g-dev \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

# build Bro, Broker & its Python binding
RUN wget -nv https://www.zeek.org/downloads/bro-2.6.1.tar.gz -O /tmp/bro.tar.gz \
 && apt-get remove -y \
        wget \
 && apt-get autoremove -y
RUN tar -xzf /tmp/bro.tar.gz \
 && cd bro-2.6.1 \
 && ./configure \
 && make \
 && make install \
 && apt-get remove -y \
        cmake \
        make \
        gcc \
        g++ \
        flex \
        bison \
        swig \
 && apt-get autoremove -y \
 && rm -rf \
        /bro \
        /tmp/bro.tar.gz

# install Python packages & dependencies
COPY vendor/python/download /tmp/python
RUN python3 -m pip install --no-deps --cache-dir=/tmp/pip \
        /tmp/python/pip-* \
        /tmp/python/setuptools-* \
        /tmp/python/wheel-* \
 && rm -f \
        /tmp/python/pip-* \
        /tmp/python/setuptools-* \
        /tmp/python/wheel-* \
 && python3 -m pip install --no-deps --cache-dir=/tmp/pip \
        /tmp/python/* \
 && rm -rf \
        /tmp/pip \
        /tmp/python \
 && apt-get remove -y \
        python3-pip \
 && apt-get autoremove -y
