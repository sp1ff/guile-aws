#!/bin/sh

version=v2.680.0

for f in $(ls -1 *.json); do
    wget -qO $f https://github.com/aws/aws-sdk-js/raw/$version/apis/$f
done
