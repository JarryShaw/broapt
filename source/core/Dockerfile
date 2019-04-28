# basic info
FROM library/centos:7
LABEL version=2019.04.28

# set up environment variables
ENV LANG "C.UTF-8"
ENV LC_ALL "C.UTF-8"
ENV PYTHONIOENCODING "UTF-8"
ENV PATH="/opt/bro/bin:${PATH}"

# install, Bro, Python 3 & all requirements
RUN yum update -y \
 && yum install -y \
        https://centos7.iuscommunity.org/ius-release.rpm \
 && yum install -y \
        make \
        ## python36u is actually dependency of the latter
        ## but we keep it here as a good remainder
        python36u \
        python36u-pip \
        ## dependency of python-magic
        ## python-magic on yum is of Python 2.7
        file

# install Bro
COPY vendor/archive/network-bro.repo /etc/yum.repos.d/
RUN yum install -y bro

# install Python packages & dependencies
COPY vendor/python /tmp/python
RUN python3.6 -m pip install --no-deps --cache-dir=/tmp/pip \
        /tmp/python/setuptools-* \
        /tmp/python/pip-* \
        /tmp/python/wheel-* \
 && rm -f \
        /tmp/python/pip-* \
        /tmp/python/setuptools-* \
        /tmp/python/wheel-* \
 && python3.6 -m pip install --no-deps --cache-dir=/tmp/pip \
        /tmp/python/*

# copy source
COPY source /source

# cleanup process
RUN rm -rf \
        ## Python archives
        /tmp/python \
        /tmp/pip \
 && yum clean all -y
