#!/bin/bash

pwd=`pwd`
kernel=`readlink -f /lib/modules/$(uname -r)/build/`/
autogen=${pwd}/autogen.sh

chmod a+x ${autogen}
sh -c ${autogen}

./configure --with-linux=${kernel} --with-linux-obj=${kernel}
make -j8
