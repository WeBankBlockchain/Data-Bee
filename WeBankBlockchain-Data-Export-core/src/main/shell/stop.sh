#!/usr/bin/env bash

for i in $(ps -ef|grep supervisord|grep -i export| awk '{print $2}')
do
    kill -9 $i
done

for j in $(ps -ef|grep -i `pwd`|grep -i WeBankBlockchain-Data-Export |grep -v grep| awk '{print $2}')
do
    kill -9 $j
done
echo "Stop succeed!"
