# basic info
FROM library/ubuntu:16.04
LABEL version 2.6.1

# set up environment variables
ENV LANG "C.UTF-8"
ENV LC_ALL "C.UTF-8"
ENV PYTHONIOENCODING "UTF-8"

# install, Bro, Python 3 & all requirements
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
 && apt-get remove -y \
        wget \
 && apt-get autoremove -y
RUN tar -xzf /tmp/bro-2.6.1.tar.gz \
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
        /bro-2.6.1 \
        /tmp/bro-2.6.1.tar.gz
ENV PATH="/usr/local/bro/bin:${PATH}"

# set entrypoint
ENTRYPOINT [ "/usr/local/bro/bin/bro" ]
CMD [ "--help" ]
