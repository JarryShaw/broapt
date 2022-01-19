# basic info
FROM library/ubuntu:16.04
LABEL LABEL org.opencontainers.image.title="broapt" \
      org.opencontainers.image.description="A system for detecting APT attacks in real-time" \
      org.opencontainers.image.url="https://broapt.jarryshaw.me/" \
      org.opencontainers.image.source="https://github.com/JarryShaw/BroAPT" \
      org.opencontainers.image.version="2020.10.11" \
      org.opencontainers.image.licenses='Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International Public License'

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
        ## python3.7 is actually dependency of the latter
        ## but we keep it here as a good remainder
        python3.7 \
        python3-pip \
        python3-setuptools \
        python3-wheel \
        ## do not directly install python3-yaml
        ## install its dependency libyaml instead
        # python3-yaml \
        libyaml-0-2 \
 && ln -sf /usr/bin/python3.7 /usr/bin/python3

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

# cleanup process
RUN rm -rf \
        ## apt repository lists
        /var/lib/apt/lists/* \
        ## Python dependencies
        /tmp/python \
        /tmp/pip \
 ## do not uninstall pip, setuptools & wheel at all
 # && python3 -m pip uninstall -y \
 #        wheel \
 #        setuptools \
 #        pip \
 && apt-get remove -y --auto-remove \
        software-properties-common \
 #        python3-pip \
 #        python3-setuptools \
 #        python3-wheel \
 && apt-get autoremove -y \
 && apt-get autoclean \
 && apt-get clean

# final setup
RUN ln -sf /usr/bin/python3.7 /usr/bin/python3

# set working directory
WORKDIR /source

# set entry point
ENTRYPOINT [ "bash", "/source/init.sh" ]

# copy source
COPY source /source
