#!/bin/sh
SYSTEM_CDK=$(find /usr/lib -name libcdk.a | head -n 1)
cp "$SYSTEM_CDK" ./deps/cdk-5.0-20161210/libcdk.a
ls -l ./deps/cdk-5.0-20161210/libcdk.a
sleep 3
make www
#
#END
