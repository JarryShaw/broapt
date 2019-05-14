# basic info
FROM library/centos:7
LABEL version=2019.05.14

# set up environment variables
ENV PYTHONIOENCODING="UTF-8"
ENV PATH="/opt/bro/bin:${PATH}"

# install, Bro, Python 3 & all requirements
COPY vendor/archive/network-bro.repo /etc/yum.repos.d/
RUN yum install -y \
        https://centos7.iuscommunity.org/ius-release.rpm \
 && yum install -y \
        bro \
        ## python36u is actually dependency of the latters
        ## but we keep it here as a good remainder
        python36u \
        python36u-pip \
        python36u-setuptools \
        ## dependency of python-magic
        ## python-magic on yum is of Python 2.7
        file \
        ## dependency of python36-PyYAML
        ## install PyYAML manually
        libyaml \
 && ln -sf /usr/bin/python3.6 /usr/bin/python3

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
        ## Python archives
        /tmp/python \
        /tmp/pip \
 ## do not uninstall pip, setuptools & wheel at all
 # && python3 -m pip uninstall -y \
 #        wheel \
 #        setuptools \
 #        pip \
 ## do not remove pip & setuptools from yum
 # && yum erase -y \
 #        python36u-pip \
 #        python36u-setuptools \
 && yum clean all -y

# copy source
COPY client /broapt
