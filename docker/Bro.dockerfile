# basic info
FROM library/ubuntu:16.04
LABEL version 2.6.1

# set up environment variables
ENV LANG "C.UTF-8"
ENV LC_ALL "C.UTF-8"
ENV PYTHONIOENCODING "UTF-8"
ENV PATH="/usr/local/bro/bin:${PATH}"

# install, Bro & all requirements
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        software-properties-common \
 && add-apt-repository --yes ppa:deadsnakes/ppa
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        wget \
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
        ## build with Python 3.6 instead
        python3.6-dev \
        swig \
        zlib1g-dev

# build Bro
RUN wget -nv --no-check-certificate \
        https://www.zeek.org/downloads/bro-2.6.1.tar.gz -O /tmp/bro-2.6.1.tar.gz
RUN tar -xzf /tmp/bro-2.6.1.tar.gz \
 && cd bro-2.6.1 \
 && ./configure \
        --with-python=/usr/bin/python3.6 \
 && make \
 && make install

RUN rm -rf \
        ## apt repository lists
        /var/lib/apt/lists/* \
        ## Bro build & archive
        /bro-2.6.1 \
        /tmp/bro-2.6.1.tar.gz \
 && apt-get remove -y --auto-remove \
        wget \
        software-properties-common \
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

# set entrypoint
ENTRYPOINT [ "/usr/local/bro/bin/bro" ]
CMD [ "--help" ]
