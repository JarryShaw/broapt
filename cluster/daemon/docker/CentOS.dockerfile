# basic info
FROM library/centos:7

# set up environment variables
ENV PYTHONIOENCODING="UTF-8"

# install Python 3.6
RUN yum install -y \
        https://centos7.iuscommunity.org/ius-release.rpm \
 && yum install -y \
        ## python36u is actually dependency of the latter
        ## but we keep it here as a good remainder
        python36u \
        python36u-pip \
        python36u-setuptools \
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
        ## Python archives
        /tmp/pip \
 ## do not remove pip, setuptools & wheel
 # && python3 -m pip uninstall -y \
 #        wheel \
 #        setuptools \
 #        pip \
 # && yum erase -y \
 #        python36u-pip \
 #        python36u-setuptools \
 && yum clean all -y

# entrypoint
ENTRYPOINT [ "pyinstaller" ]
CMD [ "--help" ]

# copy source
WORKDIR /broaptd
COPY . /broaptd
