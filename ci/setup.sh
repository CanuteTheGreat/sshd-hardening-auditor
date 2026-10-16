#!/bin/sh
# Provisions real dependencies the tests exercise (runs inside the CI container).
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq openssh-server >/dev/null
mkdir -p /run/sshd
ssh-keygen -A >/dev/null
