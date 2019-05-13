#!/usr/bin/env bash

set -ex

###############################################################################
# Requirements
###############################################################################

apt-get update
apt-get install -y --no-install-recommends \
    curl \
    gcc \
    git \
    lib32gcc1 \
    lib32ncurses5 \
    lib32stdc++6 \
    lib32z1 \
    libc6-i386 \
    libgl1-mesa-dev \
    python-dev \
    python-pip \
    python-tk \
    software-properties-common \
    wget
add-apt-repository -y \
    ppa:webupd8team/java
apt-get update
echo oracle-java8-installer shared/accepted-oracle-license-v1-1 select true | /usr/bin/debconf-set-selections
apt-get install -y oracle-java8-installer
apt-get install -y python-setuptools
apt-get clean

###############################################################################
# Android SDK
###############################################################################

wget http://dl.google.com/android/android-sdk_r24.2-linux.tgz
tar -xvf android-sdk_r24.2-linux.tgz

export ANDROID_HOME=$HOME/android-sdk-linux/
export PATH=$PATH:$ANDROID_HOME/tools
export PATH=$PATH:$ANDROID_HOME/platform-tools

###############################################################################
# Android 16 package
###############################################################################

echo y | android update sdk --filter platform-tools --no-ui --force -a
echo y | android update sdk --filter tools --no-ui --force -a
echo y | android update sdk --filter android-16 --no-ui --force -a
echo y | android update sdk --filter sys-img-armeabi-v7a-android-16 --no-ui -a

###############################################################################
# Repository
###############################################################################

git clone --recursive https://github.com/alexMyG/AndroPyTool.git
wget https://github.com/pjlantz/droidbox/releases/download/v4.1.1/DroidBox411RC.tar.gz
tar -zxvf DroidBox411RC.tar.gz
cp -r DroidBox_4.1.1/images AndroPyTool/DroidBox_AndroPyTool/images
touch AndroPyTool/avclass/__init__.py

###############################################################################
# DroidBox
###############################################################################

chmod 744 AndroPyTool/DroidBox_AndroPyTool/*.sh

echo "no" | AndroPyTool/DroidBox_AndroPyTool/createDroidBoxDevice.sh

###############################################################################
# Python Libraries
###############################################################################

pip install -r AndroPyTool/requirements.txt
