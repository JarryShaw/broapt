# basic info
FROM library/ubuntu:16.04

# set up environment variables
ENV LANG "C.UTF-8"
ENV LC_ALL "C.UTF-8"
ENV PYTHONIOENCODING "UTF-8"

# install, Python 3.6
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        software-properties-common \
 && add-apt-repository --yes ppa:deadsnakes/ppa
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ## python3.6 is actually dependency of the latter
        ## but we keep it here as a good remainder
        python3.6 \
        python3.6-dev \
        python3-pip \
        python3-setuptools \
        python3-wheel \
 && ln -sf /usr/bin/python3.6 /usr/bin/python3

# install Python dependencies
RUN python3 -m pip install --upgrade --cache-dir=/tmp/pip \
        pip \
        setuptools \
        wheel \
 && python3 -m pip install --cache-dir=/tmp/pip \
        dataclasses \
        Flask[dotenv] \
        pyinstaller

# cleanup process
RUN rm -rf \
        ## apt repository lists
        /var/lib/apt/lists/* \
        ## Python dependencies
        /tmp/pip \
 ## do not uninstall pip, setuptools & wheel
 # && python3 -m pip uninstall -y \
 #        wheel \
 #        setuptools \
 #        pip \
 && apt-get remove -y --auto-remove \
        software-properties-common \
        # python3-pip \
        # python3-setuptools \
        # python3-wheel \
 && apt-get autoremove -y \
 && apt-get autoclean \
 && apt-get clean

# final setup
RUN ln -sf /usr/bin/python3.6 /usr/bin/python3

# entrypoint
ENTRYPOINT [ "pyinstaller" ]
CMD [ "--help" ]

# copy source
WORKDIR /broaptd
COPY . /broaptd
