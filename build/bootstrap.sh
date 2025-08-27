#!/bin/bash
set -x
set -e

sudo apt update
sudo apt install -y build-essential \
    libncurses-dev \
    flex \
    bison \
    libssl-dev \
    libelf-dev \ 
    bc \
    pahole \
    dwarves \
    fakeroot \
    rsync \
    git \
    python3 \
    debhelper-compat \
    cpio

