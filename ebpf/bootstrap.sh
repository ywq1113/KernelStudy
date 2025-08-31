#!/bin/bash
set -e
set -x

sudo apt-get update
sudo apt-get install -y make clang llvm linux-tools-common libbpf-dev libelf-dev zlib1g-dev build-essential

ls /sys/kernel/btf/vmlinux
exit $?
