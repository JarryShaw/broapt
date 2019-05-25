# basic info
FROM library/ubuntu:16.04
LABEL version=1.4.0

# install ELF-Parser
COPY ./build.sh /build.sh
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        cmake \
        g++ \
        gcc \
        git \
        libboost-all-dev \
        make \
 && git clone https://github.com/jacob-baines/elfparser.git \
 && bash /build.sh

# cleanup process
RUN rm /build.sh \
 && rm -rf /elfparser \
 && apt-get remove -y --auto-remove \
        cmake \
        g++ \
        gcc \
        git \
        make \
 && apt-get autoremove -y \
 && apt-get autoclean \
 && apt-get clean

# setup entrypoint
ENTRYPOINT [ "/usr/local/bin/elfparser-cli" ]
CMD [ "--help" ]
