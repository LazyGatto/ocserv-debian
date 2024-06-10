#!/bin/sh
set -e

apt update && apt upgrade -y
apt-get install -y libgnutls28-dev libev-dev autoconf make automake git \
	ipcalc-ng libpam0g-dev liblz4-dev libseccomp-dev \
	libreadline-dev libnl-route-3-dev libkrb5-dev libradcli-dev \
	libcurl4-gnutls-dev libcjose-dev libjansson-dev liboath-dev \
	libprotobuf-c-dev libtalloc-dev libhttp-parser-dev protobuf-c-compiler \
	gperf lcov libuid-wrapper libpam-wrapper libnss-wrapper \
	libsocket-wrapper gss-ntlmssp iputils-ping \
	gawk gnutls-bin iproute2 yajl-tools tcpdump

wget https://gitlab.com/openconnect/ocserv/-/archive/1.3.0/ocserv-1.3.0.tar.gz
tar -xf ocserv-1.3.0.tar.gz
cd ocserv-1.3.0/
autoreconf -fvi
./configure && make && make check