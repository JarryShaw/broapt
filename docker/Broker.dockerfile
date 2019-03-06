# basic info
FROM library/ubuntu:16.04
LABEL version 1.1.2

# set up environment variables
ENV LANG "C.UTF-8"
ENV LC_ALL "C.UTF-8"
ENV PYTHONIOENCODING "UTF-8"
ENV PATH="/usr/local/bro/bin:${PATH}"
ENV PYTHONPATH="/usr/lib/python2.7/site-packages"

# install, Bro, Python & all requirements
RUN apt-get update \
 && apt-get upgrade -y \
 && apt-get install -y \
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
        python-dev \
        swig \
        zlib1g-dev \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

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
        --python-prefix=$(python -c 'import sys; print(sys.exec_prefix)') \
        --with-python=/usr/bin/python \
 && make install

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
 &&  apt-get remove -y \
        software-properties-common \
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

# set entrypoint
ENTRYPOINT [ "/usr/local/bro/bin/bro" ]
CMD [ "--help" ]
