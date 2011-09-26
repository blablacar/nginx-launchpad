#!/bin/bash

# this file is mostly meant to be used by the author himself.

ragel -G2 src/chunked_parser.rl

if [ $? != 0 ]; then
    echo 'Failed to generate the chunked parser.' 1>&2
    exit 1;
fi

root=`pwd`
cd ~/work
version=$1
opts=$2

if [ ! -s "nginx-$version.tar.gz" ]; then
    wget "http://sysoev.ru/nginx/nginx-$version.tar.gz" -O nginx-$version.tar.gz || exit 1
    tar -xzvf nginx-$version.tar.gz || exit 1
    if [ "$version" = "0.8.41" ]; then
        cp $root/../no-pool-nginx/nginx-$version-no_pool.patch ./
        patch -p0 < nginx-$version-no_pool.patch || exit 1
    fi
fi

#tar -xzvf nginx-$version.tar.gz || exit 1
#cp $root/../no-pool-nginx/nginx-0.8.41-no_pool.patch ./
#patch -p0 < nginx-0.8.41-no_pool.patch

if [ "$version" = "0.8.53" ]; then
    cd nginx-$version-patched/
else
    cd nginx-$version
fi

if [[ "$BUILD_CLEAN" -eq 1 || ! -f Makefile || "$root/config" -nt Makefile || "$root/util/build.sh" -nt Makefile ]]; then
    ./configure --prefix=/opt/nginx \
          --add-module=$root/../echo-nginx-module \
          --add-module=$root $opts \
          --with-debug
          #\
          #--with-http_ssl_module #\
          #--with-cc-opt="-pg" --with-ld-opt="-pg" \
  #--without-http_ssi_module  # we cannot disable ssi because echo_location_async depends on it (i dunno why?!)

fi
if [ -f /opt/nginx/sbin/nginx ]; then
    rm -f /opt/nginx/sbin/nginx
fi
if [ -f /opt/nginx/logs/nginx.pid ]; then
    kill `cat /opt/nginx/logs/nginx.pid`
fi
make -j3
make install

