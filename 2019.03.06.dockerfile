# basic info
FROM library/ubuntu:16.04
LABEL version=2019.03.06

# set up environment variables
ENV LANG "C.UTF-8"
ENV LC_ALL "C.UTF-8"
ENV PYTHONIOENCODING "UTF-8"
ENV PATH="/usr/local/bro/bin:${PATH}"
ENV PYTHONPATH="/usr/lib/python3.5/site-packages"

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
        python3-dev \
        swig \
        zlib1g-dev

# build Bro, Broker & its Python binding
RUN wget -nv https://www.zeek.org/downloads/bro-2.6.1.tar.gz -O /tmp/bro-2.6.1.tar.gz \
 && wget -nv https://www.zeek.org/downloads/broker-1.1.2.tar.gz -O /tmp/broker-1.1.2.tar.gz
RUN tar -xzf /tmp/bro-2.6.1.tar.gz \
 && cd bro-2.6.1 \
 && ./configure \
 && make \
 && make install
RUN tar -xzf /tmp/broker-1.1.2.tar.gz \
 && cd broker-1.1.2 \
 && ./configure \
        --python-home=/usr/local \
        --python-prefix=$(python3 -c 'import sys; print(sys.exec_prefix)') \
        --with-python=/usr/bin/python3 \
 && make install

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
        /tmp/python/*

# cleanup process
RUN rm -rf \
        ## apt repository lists
        /var/lib/apt/lists/* \
        ## Bro build & archive
        /bro-2.6.1 \
        /tmp/bro-2.6.1.tar.gz \
        ## Broker build & archive
        /broker-1.1.2 \
        /tmp/broker-1.1.2.tar.gz \
        ## Python dependencies
        /tmp/python \
        /tmp/pip \
 &&  apt-get remove -y \
        wget \
        ## Bro & Broker
        cmake \
        make \
        gcc \
        g++ \
        flex \
        bison \
        swig \
 && apt-get autoremove -y \
 && apt-get autoclean \
 && apt-get clean
